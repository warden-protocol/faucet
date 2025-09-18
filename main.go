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

// RateLimitMiddleware creates a rate limiting middleware.
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

// setupLogger creates and configures the logger.
func setupLogger() log.Logger {
	logLevel, err := log.ParseLevel(config.GetLogLevel())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing log level: %s", err)
		logLevel = log.InfoLevel
	}

	return log.New(
		log.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
	).Level(logLevel).With().Timestamp().Logger()
}

// setupMiddleware configures all Echo middleware.
func setupMiddleware(e *echo.Echo, logger log.Logger) {
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
}

// setupStaticRoutes configures static file routes.
func setupStaticRoutes(e *echo.Echo) {
	e.Static("/assets", "assets")
	e.File("/css/style.css", "css/style.css")
	e.File("/js/tx.js", "js/tx.js")
	e.File("/js/circle.js", "js/circle.js")
	e.File("/favicon.ico", "images/favicon.ico")
}

// homeHandler handles the home page route.
func homeHandler(page Page, logger log.Logger) echo.HandlerFunc {
	return func(c echo.Context) error {
		if csrfToken := c.Get("csrf"); csrfToken != nil {
			if token, ok := csrfToken.(string); ok {
				page.Form.CSRFToken = token
			}
		}
		page.Form.Address = c.QueryParam("addr")
		logger.Debug().Msgf("page.Form: %v", page.Form)

		return c.Render(http.StatusOK, "index", page)
	}
}

// checkTxHandler handles the transaction check route.
func checkTxHandler(f *Faucet, page Page, logger log.Logger) echo.HandlerFunc {
	return func(c echo.Context) error {
		logger.Debug().Msg("checking tx")
		logger.Debug().Msgf("Batch: %v", f.Batch)

		if len(f.Batch) == 0 {
			page.Data.TXHash = f.LatestTXHash
			return c.Render(http.StatusOK, "tx-result", page.Data)
		}

		return c.Render(http.StatusOK, "spinner", "")
	}
}

// sendTokensHandler handles the send tokens route.
func sendTokensHandler(f *Faucet, page Page, logger log.Logger) echo.HandlerFunc {
	return func(c echo.Context) error {
		var txHash string
		var httpStatusCode int

		reqCount.Inc()

		// Add timeout context for the request
		reqCtx, cancel := context.WithTimeout(c.Request().Context(), 25*time.Second)
		defer cancel()

		txHash, httpStatusCode, err := f.Send(reqCtx, c.FormValue("address"), false)
		if err != nil {
			logger.Error().Msgf("error sending tokens: %s", err)

			formData := newFormData()
			formData.Address = c.FormValue("address") // Preserve the entered address

			// Safe CSRF token handling
			if csrfToken := c.Get("csrf"); csrfToken != nil {
				if token, ok := csrfToken.(string); ok {
					formData.CSRFToken = token
				}
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
				if token, ok := csrfToken.(string); ok {
					formData.CSRFToken = token
				}
			}
			return c.Render(http.StatusOK, "form", formData)
		}

		return c.Render(http.StatusOK, "tx-status", "")
	}
}

// updateTokensHandler handles the update tokens route.
func updateTokensHandler(f *Faucet, page Page) echo.HandlerFunc {
	return func(c echo.Context) error {
		page.Data.TokensAvailable = f.TokensAvailable
		page.Data.TokensAvailablePercent = f.TokensAvailable / f.DailySupply * totalPercent

		if page.Data.TokensAvailable <= 0 {
			return c.Render(http.StatusOK, "red-cross", "")
		}

		return c.Render(http.StatusOK, "tokens-section", page.Data)
	}
}

// setupRoutes configures all application routes.
func setupRoutes(e *echo.Echo, f *Faucet, page Page, logger log.Logger) {
	e.GET("/metrics", echo.WrapHandler(promhttp.Handler()))
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	e.GET("/", homeHandler(page, logger))
	e.GET("/check-tx", checkTxHandler(f, page, logger))
	e.POST("/send-tokens", sendTokensHandler(f, page, logger))
	e.GET("/update-tokens", updateTokensHandler(f, page))
}

func main() {
	ctx := context.Background()
	e := echo.New()

	logger := setupLogger()
	setupMiddleware(e, logger)

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

	setupStaticRoutes(e)
	setupRoutes(e, f, page, logger)

	logger.Fatal().Err(e.Start(":8081"))
}
