package main

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/rs/zerolog"
	"golang.org/x/time/rate"

	"github.com/warden-protocol/wardenprotocol/cmd/faucet/pkg/config"
)

const totalPercent = 100

type Templates struct {
	templates *template.Template
}

func (t *Templates) Render(w io.Writer, name string, data any, _ echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func newTemplate() *Templates {
	return &Templates{
		templates: template.Must(template.ParseGlob("templates/*.html")),
	}
}

// these will be set as WARD not uWARD.
type Data struct {
	TokensAvailable        float64
	TokensAvailablePercent float64
	TokenSupply            float64
	DisplayTokens          bool
	Denom                  string
	TXHash                 string
	Chain                  string
}

func newData() Data {
	return Data{
		TokensAvailable:        0,
		TokensAvailablePercent: 0,
		TokenSupply:            0,
		DisplayTokens:          true,
		Denom:                  "",
		TXHash:                 "",
	}
}

type FormData struct {
	Address   string
	CSRFToken string
	Errors    map[string]string
}

func newFormData() FormData {
	return FormData{
		Address:   "",
		CSRFToken: "",
		Errors:    make(map[string]string),
	}
}

type Page struct {
	Data Data
	Form FormData
}

func newPage() Page {
	return Page{
		Data: newData(),
		Form: newFormData(),
	}
}

// RateLimitMiddleware creates a rate limiting middleware
func RateLimitMiddleware(rps int, burst int) echo.MiddlewareFunc {
	var mu sync.Mutex
	clients := make(map[string]*rate.Limiter)

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			ip := c.RealIP()

			mu.Lock()
			if _, exists := clients[ip]; !exists {
				clients[ip] = rate.NewLimiter(rate.Limit(rps), burst)
			}
			clientLimiter := clients[ip]
			mu.Unlock()

			if !clientLimiter.Allow() {
				return c.JSON(http.StatusTooManyRequests, map[string]string{
					"error": "Rate limit exceeded. Please try again later.",
				})
			}

			return next(c)
		}
	}
}

func main() {
	ctx := context.Background()
	e := echo.New()

	logLevel, err := log.ParseLevel(config.GetLogLevel())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing log level: %s", err)

		logLevel = log.InfoLevel
	}

	logger := log.New(
		log.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
	).Level(logLevel).With().Timestamp().Logger()

	if logger.GetLevel() == log.DebugLevel {
		e.Use(middleware.Logger())
	}

	// Add rate limiting: 10 requests per second per IP, burst of 20
	e.Use(RateLimitMiddleware(10, 20))

	// Add timeout middleware to prevent hanging requests
	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: 30 * time.Second,
	}))

	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup: "header:X-CSRF-Token",
	}))

	page := newPage()
	e.Renderer = newTemplate()

	f, err := InitFaucet(ctx, logger)
	if err != nil {
		e.Logger.Fatal(err)
	}

	// HTML Variables
	page.Data = Data{
		TokensAvailable:        f.TokensAvailable,
		TokensAvailablePercent: totalPercent,
		TokenSupply:            f.TokensAvailable,
		Denom:                  f.config.Denom,
		Chain:                  f.config.Chain,
		DisplayTokens:          f.config.DisplayTokens,
	}

	// Start batch process
	go f.batchProcessInterval()

	// Start refresh interval
	go f.DailyRefresh()

	e.Static("/assets", "assets")
	e.File("/css/style.css", "css/style.css")
	e.File("/js/tx.js", "js/tx.js")
	e.File("/js/circle.js", "js/circle.js")
	e.File("/favicon.ico", "images/favicon.ico")

	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	e.GET("/", func(c echo.Context) error {
		if err != nil {
			logger.Error().Msgf("unable to get session %v", err)
			return c.Render(http.StatusInternalServerError, "index", page)
		}

		if csrfToken := c.Get("csrf"); csrfToken != nil {
			page.Form.CSRFToken = csrfToken.(string)
		}
		page.Form.Address = c.QueryParam("addr")
		logger.Debug().Msgf("page.Form: %v", page.Form)

		return c.Render(http.StatusOK, "index", page)
	})

	e.GET("/check-tx", func(c echo.Context) error {
		logger.Debug().Msg("checking tx")
		logger.Debug().Msgf("Batch: %v", f.Batch)

		if len(f.Batch) == 0 {
			page.Data.TXHash = f.LatestTXHash
			return c.Render(http.StatusOK, "tx-result", page.Data)
		}

		return c.Render(http.StatusOK, "spinner", "")
	})

	e.POST("/send-tokens", func(c echo.Context) error {
		var txHash string
		var httpStatusCode int

		reqCount.Inc()

		// Add timeout context for the request
		ctx, cancel := context.WithTimeout(c.Request().Context(), 25*time.Second)
		defer cancel()

		txHash, httpStatusCode, err = f.Send(ctx, c.FormValue("address"), false)
		if err != nil {
			logger.Error().Msgf("error sending tokens: %s", err)

			formData := newFormData()
			formData.Address = c.FormValue("address") // Preserve the entered address

			// Safe CSRF token handling
			if csrfToken := c.Get("csrf"); csrfToken != nil {
				formData.CSRFToken = csrfToken.(string)
			}
			formData.Errors["address"] = err.Error()

			return c.Render(httpStatusCode, "form", formData)
		}

		if txHash != "" {
			page.Data.TokensAvailable -= f.Amount
			page.Data.TokensAvailablePercent = page.Data.TokensAvailable / page.Data.TokenSupply * totalPercent

			logger.Info().Msgf("txHash: %s", txHash)

			// Return a fresh form with new CSRF token for next submission
			formData := newFormData()
			if csrfToken := c.Get("csrf"); csrfToken != nil {
				formData.CSRFToken = csrfToken.(string)
			}
			return c.Render(http.StatusOK, "form", formData)
		}

		return c.Render(http.StatusOK, "tx-status", "")
	})

	e.GET("/update-tokens", func(c echo.Context) error {
		page.Data.TokensAvailable = f.TokensAvailable
		page.Data.TokensAvailablePercent = f.TokensAvailable / page.Data.TokenSupply * totalPercent

		if page.Data.TokensAvailable <= 0 {
			return c.Render(http.StatusOK, "red-cross", "")
		}

		return c.Render(http.StatusOK, "tokens-section", page.Data)
	})

	logger.Fatal().Err(e.Start(":8081"))
}
