# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Copy source code
COPY . .

# Build the faucet binary
RUN go build -o faucet .

# Final stage - using distroless
FROM gcr.io/distroless/static:nonroot

WORKDIR /

# Copy the binary from builder stage
COPY --from=builder /app/faucet /faucet

# Copy static assets
COPY assets/ /assets/
COPY css/ /css/
COPY js/ /js/
COPY templates/ /templates/

# Expose port
EXPOSE 8081

# Run the binary
ENTRYPOINT ["/faucet"]
