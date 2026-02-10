FROM golang:1.24-alpine AS builder

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
RUN apk --no-cache add ca-certificates libpcap

# Set working directory
WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/peer-sniffer .

# Make the binary executable
RUN chmod +x ./peer-sniffer

# Expose port (not typically used for packet capture)
EXPOSE 8080

# Create a directory for storing peer data and ensure it exists
RUN mkdir -p /root/.peerd

# Ensure .peerd directory exists and run the application
ENTRYPOINT ["/root/peer-sniffer"]