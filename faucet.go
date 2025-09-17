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

type Faucet struct {
	*sync.Mutex

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

// convertCosmosToEVM converts a Cosmos bech32 address to an Ethereum address
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
	if len(addrBytes) == 20 {
		// Direct 20-byte address
		copy(addr[:], addrBytes)
	} else if len(addrBytes) == 32 {
		// Take last 20 bytes if it's a 32-byte address
		copy(addr[:], addrBytes[12:])
	} else {
		return "", fmt.Errorf("invalid address length: %d bytes", len(addrBytes))
	}

	return addr.Hex(), nil
}

func InitFaucet(ctx context.Context, logger zerolog.Logger) (Faucet, error) {
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal().Msgf("error loading config: %s", err)
	}

	// Connect to the Ethereum client
	client, err := ethclient.Dial(cfg.Node)
	if err != nil {
		return Faucet{}, fmt.Errorf("failed to connect to the Ethereum client: %w", err)
	}

	// Parse the private key from hex string
	privateKey, err := crypto.HexToECDSA(cfg.PrivateKey)
	if err != nil {
		return Faucet{}, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Get the public key and address
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return Faucet{}, errors.New("failed to cast public key to ECDSA")
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
		return Faucet{}, fmt.Errorf("failed to get nonce: %w", err)
	}
	f.nonce = nonce

	dailySupply.Set(f.DailySupply)

	logger.Info().Msgf("EVM Faucet initialized with address: %s", fromAddress.Hex())

	return f, nil
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

// sendBatch sends tokens to multiple addresses in a single transaction with retry logic
func (f *Faucet) sendBatch(ctx context.Context, addresses []string) (string, float64, error) {
	const maxRetries = 3
	const gasPriceMultiplier = 1.2 // Increase gas price by 20% on retry

	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		// Get fresh nonce for each retry to avoid conflicts
		nonce, err := f.client.PendingNonceAt(ctx, f.fromAddress)
		if err != nil {
			return "", 0, fmt.Errorf("failed to get nonce: %w", err)
		}
		f.nonce = nonce

		// Get current gas price and increase if retrying
		gasPrice, err := f.client.SuggestGasPrice(ctx)
		if err != nil {
			return "", 0, fmt.Errorf("failed to suggest gas price: %w", err)
		}

		// Increase gas price on retries to avoid "underpriced" errors
		if retry > 0 {
			multiplier := new(big.Float).SetFloat64(gasPriceMultiplier)
			for i := 0; i < retry; i++ {
				multiplier.Mul(multiplier, big.NewFloat(gasPriceMultiplier))
			}
			gasPriceFloat := new(big.Float).SetInt(gasPrice)
			gasPriceFloat.Mul(gasPriceFloat, multiplier)
			gasPrice, _ = gasPriceFloat.Int(nil)

			f.log.Info().Msgf("retry %d: increasing gas price to %s", retry+1, gasPrice.String())
		}

		txHash, totalSent, err := f.sendBatchTransaction(ctx, addresses, gasPrice, nonce)
		if err != nil {
			lastErr = err
			f.log.Warn().Msgf("batch send attempt %d failed: %v", retry+1, err)

			// Wait before retry to avoid rapid successive failures
			if retry < maxRetries-1 {
				time.Sleep(time.Duration(retry+1) * time.Second)
			}
			continue
		}

		f.log.Info().Msgf("batch transaction successful on attempt %d: %s", retry+1, txHash)
		return txHash, totalSent, nil
	}

	return "", 0, fmt.Errorf("failed after %d retries, last error: %w", maxRetries, lastErr)
}

// sendBatchTransaction creates and sends a batch transaction to multiple addresses
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
		tx := types.NewTransaction(
			nonce+uint64(i),
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

		successfulAddresses = append(successfulAddresses, address)
		totalSent += f.Amount
		lastTxHash = signedTx.Hash().Hex()

		// Log both original and converted address for transparency
		if address != evmAddress {
			f.log.Info().
				Msgf("sent %f %s to %s (converted from %s), tx: %s", f.Amount, f.config.Denom, evmAddress, address, lastTxHash)
		} else {
			f.log.Info().Msgf("sent %f %s to %s, tx: %s", f.Amount, f.config.Denom, evmAddress, lastTxHash)
		}
	}

	// Update nonce to the last used nonce + 1
	f.nonce = nonce + uint64(len(successfulAddresses))

	if len(successfulAddresses) == 0 {
		return "", 0, errors.New("failed to send to any addresses")
	}

	if len(successfulAddresses) < len(addresses) {
		f.log.Warn().
			Msgf("only sent to %d out of %d addresses", len(successfulAddresses), len(addresses))
	}

	return lastTxHash, totalSent, nil
}

func (f *Faucet) sendToAddress(ctx context.Context, toAddr string) (string, error) {
	toAddress := common.HexToAddress(toAddr)

	// Convert amount to wei
	amount := new(big.Float).SetFloat64(f.config.Amount)
	multiplierInt := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(f.config.Exponent)), nil)
	multiplier := new(big.Float).SetInt(multiplierInt)
	amount.Mul(amount, multiplier)

	amountWei := new(big.Int)
	amount.Int(amountWei)

	// Get current gas price
	gasPrice, err := f.client.SuggestGasPrice(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to suggest gas price: %w", err)
	}

	// Create the transaction
	tx := types.NewTransaction(
		f.nonce,
		toAddress,
		amountWei,
		21000, // Standard gas limit for ETH transfer
		gasPrice,
		nil,
	)

	// Get the chain ID
	chainID, err := f.client.NetworkID(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get network ID: %w", err)
	}

	// Sign the transaction
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), f.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Send the transaction
	err = f.client.SendTransaction(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %w", err)
	}

	// Increment nonce for next transaction
	f.nonce++

	return signedTx.Hash().Hex(), nil
}

// DailyRefresh resets the available tokens daily
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
