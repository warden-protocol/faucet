package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cosmos/cosmos-sdk/types/bech32"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/rs/zerolog"

	"github.com/warden-protocol/faucet/pkg/config"
)

const multiplyNumber = 1

type Faucet struct {
	*sync.Mutex
	nonceMutex sync.Mutex // Separate mutex for nonce management

	log             zerolog.Logger
	config          config.Config
	client          *ethclient.Client
	privateKey      *ecdsa.PrivateKey
	fromAddress     common.Address
	DailySupply     float64
	TokensAvailable float64
	Amount          float64
	Batch           []string
	LatestTXHash    string
	DisplayTokens   bool
	nonce           uint64
}

const (
	mutexLocked = 1
	dailyHours  = 24
)

func validAddress(addr string, config config.Config) error {
	// Try EVM address first
	if common.IsHexAddress(addr) {
		return nil
	}

	// Try Cosmos bech32 address
	prefix, _, err := bech32.DecodeAndConvert(addr)
	if err != nil {
		reqInvalidAddrCount.Inc()
		return fmt.Errorf(
			"invalid address: must be either a valid Ethereum address (0x...) or bech32 address",
		)
	}

	// Parse accepted prefixes from config
	acceptedPrefixes := strings.Split(config.AcceptedPrefixes, ",")
	for i, p := range acceptedPrefixes {
		acceptedPrefixes[i] = strings.TrimSpace(p)
	}

	for _, acceptedPrefix := range acceptedPrefixes {
		if prefix == acceptedPrefix {
			return nil
		}
	}

	reqInvalidAddrCount.Inc()
	return fmt.Errorf(
		"unsupported bech32 prefix: %s (accepted: %s)",
		prefix,
		config.AcceptedPrefixes,
	)
}

// convertCosmosToEVM converts a Cosmos bech32 address to an Ethereum address.
func convertCosmosToEVM(bech32Addr string) (string, error) {
	if common.IsHexAddress(bech32Addr) {
		// Already an EVM address
		return strings.ToLower(bech32Addr), nil
	}

	// Decode bech32 address
	_, addrBytes, err := bech32.DecodeAndConvert(bech32Addr)
	if err != nil {
		return "", fmt.Errorf("failed to decode bech32 address: %w", err)
	}

	// Convert to Ethereum address
	var addr common.Address
	switch len(addrBytes) {
	case 20:
		// Direct 20-byte address
		copy(addr[:], addrBytes)
	case 32:
		// Take last 20 bytes if it's a 32-byte address
		copy(addr[:], addrBytes[12:])
	default:
		return "", fmt.Errorf("invalid address length: %d bytes", len(addrBytes))
	}

	return addr.Hex(), nil
}

// getAndIncrementNonce safely gets and increments nonce for concurrent access.
func (f *Faucet) getAndIncrementNonce(ctx context.Context, count uint64) (uint64, error) {
	f.nonceMutex.Lock()
	defer f.nonceMutex.Unlock()

	// Get fresh nonce from network periodically to stay in sync
	pendingNonce, err := f.client.PendingNonceAt(ctx, f.fromAddress)
	if err != nil {
		return 0, fmt.Errorf("failed to get pending nonce: %w", err)
	}

	// Use the maximum of our tracked nonce and the network nonce
	if pendingNonce > f.nonce {
		f.log.Debug().Msgf("updating tracked nonce from %d to %d", f.nonce, pendingNonce)
		f.nonce = pendingNonce
	}

	currentNonce := f.nonce
	f.nonce += count // Reserve the next 'count' nonces

	f.log.Debug().Msgf("allocated nonce range %d-%d", currentNonce, currentNonce+count-1)
	return currentNonce, nil
}

// categorizeError categorizes error types for better debugging.
func categorizeError(err error) string {
	errMsg := err.Error()
	switch {
	case strings.Contains(errMsg, "nonce"):
		return "nonce_conflict"
	case strings.Contains(errMsg, "replacement") || strings.Contains(errMsg, "underpriced"):
		return "replacement_underpriced"
	case strings.Contains(errMsg, "insufficient"):
		return "insufficient_funds"
	case strings.Contains(errMsg, "gas"):
		return "gas_related"
	case strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "context"):
		return "network_timeout"
	default:
		return "unknown"
	}
}

// waitForTransactionReceipt waits for a transaction to be mined and confirmed.
func (f *Faucet) waitForTransactionReceipt(
	ctx context.Context,
	txHash common.Hash,
	timeout time.Duration,
) error {
	f.log.Debug().Msgf("waiting for transaction receipt: %s", txHash.Hex())

	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("transaction %s not mined within %v", txHash.Hex(), timeout)
		case <-ticker.C:
			receipt, err := f.client.TransactionReceipt(waitCtx, txHash)
			if err != nil {
				// Transaction not yet mined, continue waiting
				continue
			}

			if receipt.Status == 0 {
				return fmt.Errorf("transaction %s failed (status: 0)", txHash.Hex())
			}

			f.log.Info().
				Msgf("transaction %s confirmed in block %d", txHash.Hex(), receipt.BlockNumber.Uint64())
			return nil
		}
	}
}

// validateProductionConfig checks if the configuration is suitable for production.
func validateProductionConfig(cfg config.Config, logger zerolog.Logger) {
	warnings := []string{}

	if cfg.BatchInterval < 30*time.Second {
		warnings = append(
			warnings,
			fmt.Sprintf(
				"BatchInterval (%v) is very short, consider at least 30s for production",
				cfg.BatchInterval,
			),
		)
	}

	if cfg.BatchLimit > 10 {
		warnings = append(
			warnings,
			fmt.Sprintf(
				"BatchLimit (%d) is high, consider reducing for better reliability",
				cfg.BatchLimit,
			),
		)
	}

	if cfg.DailyLimit > 100000 {
		warnings = append(
			warnings,
			fmt.Sprintf("DailyLimit (%d) is very high, ensure sufficient funds", cfg.DailyLimit),
		)
	}

	for _, warning := range warnings {
		logger.Warn().Msg(warning)
	}

	if len(warnings) > 0 {
		logger.Info().Msg("Consider adjusting configuration for production environment")
	}
}

func InitFaucet(ctx context.Context, logger zerolog.Logger) (*Faucet, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal().Msgf("error loading config: %s", err)
	}

	// Validate production configuration
	validateProductionConfig(cfg, logger)

	// Connect to the Ethereum client
	client, err := ethclient.Dial(cfg.Node)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the Ethereum client: %w", err)
	}

	// Parse the private key from hex string
	privateKey, err := crypto.HexToECDSA(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Get the public key and address
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to cast public key to ECDSA")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	f := Faucet{
		config:          cfg,
		client:          client,
		privateKey:      privateKey,
		fromAddress:     fromAddress,
		Mutex:           &sync.Mutex{},
		Batch:           []string{},
		log:             logger,
		TokensAvailable: float64(cfg.DailyLimit),
		DailySupply:     float64(cfg.DailyLimit),
		Amount:          cfg.Amount,
		DisplayTokens:   cfg.DisplayTokens,
	}

	// Get the initial nonce
	nonce, err := client.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get nonce: %w", err)
	}
	f.nonce = nonce

	dailySupply.Set(f.DailySupply)

	logger.Info().Msgf("EVM Faucet initialized with address: %s", fromAddress.Hex())

	return &f, nil
}

func addressInBatch(batch []string, addr string) bool {
	return slices.Contains(batch, addr)
}

func (f *Faucet) Send(ctx context.Context, addr string, force bool) (string, int, error) {
	f.Lock()
	defer f.Unlock()

	if f.TokensAvailable <= 0 {
		return "",
			http.StatusTooManyRequests,
			errors.New("no tokens available, please come back tomorrow")
	}

	// Normalize address to lowercase for EVM addresses
	if strings.HasPrefix(addr, "0x") {
		addr = strings.ToLower(addr)
	}

	if len(f.Batch) < f.config.BatchLimit && !force {
		if strings.Contains(f.config.Blacklist, addr) {
			return "", http.StatusUnprocessableEntity, fmt.Errorf("address %s is blacklisted", addr)
		}

		if err := validAddress(addr, f.config); err != nil {
			return "", http.StatusUnprocessableEntity, err
		}

		if addressInBatch(f.Batch, addr) {
			return "", http.StatusUnprocessableEntity, errors.New("address already in batch")
		}

		f.Batch = append(f.Batch, addr)
		batchSize.Inc()
		return "", 0, nil
	}

	if len(f.Batch) == 0 {
		return "", http.StatusBadRequest, errors.New("no addresses in batch to send to")
	}

	// Send as a single batch transaction to save on gas
	txHash, totalSent, err := f.sendBatch(ctx, f.Batch)
	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("failed to send batch: %w", err)
	}

	f.TokensAvailable -= totalSent
	f.log.Debug().Msgf("tokens available: %f", f.TokensAvailable)
	f.log.Info().Msgf("batch sent to %d addresses, total: %f %s, tx: %s",
		len(f.Batch), totalSent, f.config.Denom, txHash)
	dailySupply.Set(f.TokensAvailable)

	f.LatestTXHash = txHash
	f.Batch = []string{}

	return txHash, http.StatusOK, nil
}

// sendBatch sends tokens to multiple addresses with robust retry logic.
func (f *Faucet) sendBatch(ctx context.Context, addresses []string) (string, float64, error) {
	const maxRetries = 5
	const baseGasPriceMultiplier = 2.0 // Start with 100% increase for production
	const maxGasPriceMultiplier = 20.0 // Cap at 20x for replacement transactions

	var lastErr error
	addressCount := uint64(len(addresses))

	for retry := 0; retry < maxRetries; retry++ {
		// Get nonce range for this batch using thread-safe function
		nonce, err := f.getAndIncrementNonce(ctx, addressCount)
		if err != nil {
			lastErr = fmt.Errorf("failed to get nonce: %w", err)
			f.log.Error().Msgf("retry %d: %v", retry+1, lastErr)
			continue
		}

		f.log.Debug().
			Msgf("retry %d: using nonce range %d-%d", retry+1, nonce, nonce+addressCount-1)

		// Get current gas price and increase significantly on retries
		gasPrice, err := f.client.SuggestGasPrice(ctx)
		if err != nil {
			lastErr = fmt.Errorf("failed to suggest gas price: %w", err)
			f.log.Error().Msgf("retry %d: %v", retry+1, lastErr)
			continue
		}

		// Increase gas price more aggressively on retries for production
		if retry > 0 {
			// More aggressive scaling: 2x, 4x, 8x, 16x, 20x
			multiplier := baseGasPriceMultiplier * float64(
				int64(multiplyNumber)<<retry,
			) // Exponential increase
			if multiplier > maxGasPriceMultiplier {
				multiplier = maxGasPriceMultiplier
			}

			originalGasPrice := new(big.Int).Set(gasPrice)
			gasPriceFloat := new(big.Float).SetInt(gasPrice)
			gasPriceFloat.Mul(gasPriceFloat, big.NewFloat(multiplier))
			gasPrice, _ = gasPriceFloat.Int(nil)

			f.log.Warn().
				Msgf("retry %d: aggressively increasing gas price from %s to %s (%.1fx) for replacement",
					retry+1, originalGasPrice.String(), gasPrice.String(), multiplier)
		}

		txHash, totalSent, err := f.sendBatchTransaction(ctx, addresses, gasPrice, nonce)
		if err != nil {
			lastErr = err
			f.log.Warn().Msgf("batch send attempt %d failed: %v", retry+1, err)

			// Check if it's a nonce-related error and force a longer wait
			if strings.Contains(err.Error(), "nonce") ||
				strings.Contains(err.Error(), "replacement") ||
				strings.Contains(err.Error(), "underpriced") {
				waitTime := time.Duration(retry+1) * 10 * time.Second // 10s, 20s, 30s, 40s
				f.log.Warn().
					Msgf("nonce/replacement conflict detected, waiting %v before next attempt", waitTime)
				time.Sleep(waitTime)
			}
			continue
		}

		f.log.Info().Msgf("batch transaction successful on attempt %d: %s", retry+1, txHash)
		return txHash, totalSent, nil
	}

	// Categorize the final error for better debugging
	errType := categorizeError(lastErr)

	f.log.Error().
		Msgf("batch transaction failed permanently (type: %s) after %d retries: %v", errType, maxRetries, lastErr)
	return "", 0, fmt.Errorf(
		"failed after %d retries (error_type: %s), last error: %w",
		maxRetries,
		errType,
		lastErr,
	)
}

// sendBatchTransaction creates and sends a batch transaction to multiple addresses.
func (f *Faucet) sendBatchTransaction(
	ctx context.Context,
	addresses []string,
	gasPrice *big.Int,
	nonce uint64,
) (string, float64, error) {
	// Convert amount to wei
	amount := new(big.Float).SetFloat64(f.config.Amount)
	multiplierInt := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(f.config.Exponent)), nil)
	multiplier := new(big.Float).SetInt(multiplierInt)
	amount.Mul(amount, multiplier)

	amountWei := new(big.Int)
	amount.Int(amountWei)

	var totalSent float64
	var successfulAddresses []string
	var lastTxHash string

	// For now, we'll send individual transactions but with proper retry logic
	// TODO: Implement true batching using smart contract for even better efficiency
	for i, address := range addresses {
		// Convert bech32 address to EVM address if needed
		evmAddress, err := convertCosmosToEVM(address)
		if err != nil {
			f.log.Error().Msgf("failed to convert address %s: %v", address, err)
			continue
		}

		toAddress := common.HexToAddress(evmAddress)

		// Create the transaction with incremented nonce for each address
		// Safe conversion: i is always positive and within bounds since it's from range
		txNonce := nonce + uint64(i) //nolint:gosec // i is from range iteration, always safe
		tx := types.NewTransaction(
			txNonce,
			toAddress,
			amountWei,
			21000, // Standard gas limit for ETH transfer
			gasPrice,
			nil,
		)

		// Get the chain ID
		chainID, err := f.client.NetworkID(ctx)
		if err != nil {
			return "", 0, fmt.Errorf("failed to get network ID: %w", err)
		}

		// Sign the transaction
		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), f.privateKey)
		if err != nil {
			return "", 0, fmt.Errorf("failed to sign transaction to %s: %w", evmAddress, err)
		}

		// Send the transaction
		err = f.client.SendTransaction(ctx, signedTx)
		if err != nil {
			f.log.Error().Msgf("failed to send transaction to %s: %v", evmAddress, err)
			continue
		}

		txHash := signedTx.Hash()
		f.log.Info().Msgf("transaction submitted to %s: %s", evmAddress, txHash.Hex())

		// Wait for transaction to be mined (with shorter timeout for individual txs)
		if waitErr := f.waitForTransactionReceipt(ctx, txHash, 60*time.Second); waitErr != nil {
			f.log.Error().Msgf("transaction to %s failed to confirm: %v", evmAddress, waitErr)
			continue
		}

		successfulAddresses = append(successfulAddresses, address)
		totalSent += f.Amount
		lastTxHash = txHash.Hex()

		// Log both original and converted address for transparency
		if address != evmAddress {
			f.log.Info().
				Msgf("confirmed %f %s to %s (converted from %s), tx: %s", f.Amount, f.config.Denom, evmAddress, address, lastTxHash)
		} else {
			f.log.Info().Msgf("confirmed %f %s to %s, tx: %s", f.Amount, f.config.Denom, evmAddress, lastTxHash)
		}
	}

	// Nonce is already managed by getAndIncrementNonce function
	if len(successfulAddresses) == 0 {
		return "", 0, errors.New("failed to send to any addresses")
	}

	if len(successfulAddresses) < len(addresses) {
		f.log.Warn().
			Msgf("only sent to %d out of %d addresses", len(successfulAddresses), len(addresses))
	}

	return lastTxHash, totalSent, nil
}


// DailyRefresh resets the available tokens daily.
func (f *Faucet) DailyRefresh() {
	for {
		now := time.Now()
		nextDay := now.AddDate(0, 0, 1).Truncate(dailyHours * time.Hour)
		durationUntilNextDay := time.Until(nextDay)

		f.log.Info().Msgf("next token refresh in %s", durationUntilNextDay)
		time.Sleep(durationUntilNextDay)

		f.Lock()
		f.TokensAvailable = f.DailySupply
		f.Unlock()
	}
}

func (f *Faucet) batchProcessInterval() {
	f.log.Info().Msgf("starting batch process interval")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ticker := time.NewTicker(f.config.BatchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if len(f.Batch) > 0 {
				if txHash, _, err := f.Send(ctx, "", true); err != nil {
					reqErrorCount.Inc()
					f.log.Error().Msgf("error sending batch: %s", err)
				} else {
					f.log.Debug().Msgf("tx hash %s", txHash)
					f.LatestTXHash = txHash

					batchSendCount.Inc()
					batchSize.Set(0)
				}
			}
		}
	}
}
