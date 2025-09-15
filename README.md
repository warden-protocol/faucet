# Warden Faucet

This enhanced EVM faucet supports both Ethereum (EVM) and Cosmos bech32 address formats, allowing seamless interaction between Cosmos users and EVM-compatible networks.

## Key Features

### 🌐 Universal Address Support

- **EVM Addresses**: Standard Ethereum hex addresses (0x...)
- **Bech32 Addresses**: Cosmos-style addresses with configurable prefixes
- **Automatic Conversion**: Seamless conversion between address formats
- **Universal Compatibility**: Works with any EVM-compatible network

## Usage

### Environment Configuration

```bash
# Required
PRIVATE_KEY=your_private_key_hex
NODE=https://evm.barra.wardenprotocol.org
CHAIN_ID=9191

# Optional - Configure accepted bech32 prefixes
ACCEPTED_PREFIXES=warden

# Standard faucet configuration
AMOUNT=0.1
DENOM=WARD
DAILY_LIMIT=10
```

### Building

```bash
go build -o faucet .
```

### Running

```bash
./faucet
```

## How It Works

1. **Address Validation**: The faucet first validates the input address

   - If it's a valid EVM address (0x...), it's used directly
   - If it's a bech32 address, the prefix is checked against `ACCEPTED_PREFIXES`

2. **Address Conversion**: For bech32 addresses:

   - The address is decoded to get the raw bytes
   - Raw bytes are converted to an Ethereum address format
   - Funds are sent to the corresponding EVM address

3. **Transparent Logging**: The faucet logs both the original and converted addresses:
   ```
   sent 0.100000 ETH to 0x742d35Cc6634C0532925a3b8D93Cc0638Ad5DbA8 (converted from warden1wskntnrxxnq9x2f95wudj0xqvw9dtkag46y5kk), tx: 0x...
   ```

## Testing

Run the comprehensive test suite:

```bash
go test -v .
```

Tests cover:

- Cosmos to EVM address conversion
- Address validation with configurable prefixes
- Error handling for invalid addresses
