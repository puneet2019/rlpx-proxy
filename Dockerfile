FROM golang:1.24-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /rlpx-proxy ./cmd/rlpx-proxy

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /rlpx-proxy /usr/local/bin/rlpx-proxy
ENTRYPOINT ["rlpx-proxy"]
