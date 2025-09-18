package main

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	//nolint:gochecknoglobals // Prometheus metrics are conventionally global
	batchSendCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "faucet",
		Name:      "batch_send_count_total",
		Help:      "The total number of sent batches (success or error)",
	})

	//nolint:gochecknoglobals // Prometheus metrics are conventionally global
	batchSize = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "faucet",
		Name:      "batch_size",
		Help:      "The size of the batch of addresses waiting for tokens",
	})

	//nolint:gochecknoglobals // Prometheus metrics are conventionally global
	reqCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "faucet",
		Name:      "req_count_total",
		Help:      "The total number of faucet requests",
	})

	//nolint:gochecknoglobals // Prometheus metrics are conventionally global
	reqInvalidAddrCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "faucet",
		Name:      "req_invalid_addr_count_total",
		Help:      "The total number of failed requests for invalid address",
	})

	//nolint:gochecknoglobals // Prometheus metrics are conventionally global
	reqErrorCount = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "faucet",
		Name:      "req_error_count_total",
		Help:      "The total number of failed requests for errors during send",
	})

	//nolint:gochecknoglobals // Prometheus metrics are conventionally global
	dailySupply = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "faucet",
		Name:      "daily_limit",
		Help:      "The total amount left of tokens available per day",
	})
)
