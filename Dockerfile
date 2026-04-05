FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o hysteria-server .

# ─── Runtime ─────────────────────────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/hysteria-server .

# Default ports:
#  443  - Hysteria2 (QUIC/UDP)
#  8080 - Captive portal HTTP
#  8443 - MTProto proxy
EXPOSE 443/udp 8080/tcp 8443/tcp

ENTRYPOINT ["/app/hysteria-server"]
