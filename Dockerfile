# Multi-stage build for rlpx-proxy.
# Supports multi-platform builds via docker buildx (linux/amd64, linux/arm64).
#
# Usage:
#   docker build -t rlpx-proxy .
#   docker buildx build --platform linux/amd64,linux/arm64 -t rlpx-proxy .

FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETOS TARGETARCH

RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /rlpx-proxy ./cmd/rlpx-proxy

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /rlpx-proxy /usr/local/bin/rlpx-proxy
EXPOSE 30303/tcp 30301/udp 30302/udp 8080/tcp
ENTRYPOINT ["rlpx-proxy"]
