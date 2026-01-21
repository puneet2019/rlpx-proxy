FROM golang:1.19-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git build-base linux-headers libpcap-dev

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN go build -o peer-sniffer ./cmd/peer-sniffer

FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates libpcap-dev

# Create non-root user
RUN addgroup -g 65532 nonroot && \
    adduser -D -u 65532 -G nonroot nonroot

# Set working directory
WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/peer-sniffer .

# Change ownership to non-root user
RUN chown -R nonroot:nonroot /root/

# Switch to non-root user
USER nonroot

# Expose port (not typically used for packet capture)
EXPOSE 8080

# Run the application
CMD ["./peer-sniffer", "start"]