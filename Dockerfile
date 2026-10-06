# syntax=docker/dockerfile:1

# Use the same ntfy version here as for your ntfy server,
# because the CLI works directly on the server's auth database.
ARG NTFY_VERSION=latest

# --- Build Go binary ---
FROM golang:1.27-alpine AS builder
ARG VERSION=dev
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN go test ./... \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/ntfywui ./cmd/ntfywui

# --- ntfy CLI binary from the official image ---
FROM binwiederhier/ntfy:${NTFY_VERSION} AS ntfy

# --- Runtime ---
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 ntfywui && adduser -S -u 10001 -G ntfywui -h /home/ntfywui ntfywui \
 && mkdir -p /data && chown ntfywui:ntfywui /data
WORKDIR /app
COPY --from=builder /out/ntfywui /usr/local/bin/ntfywui
COPY --from=ntfy /usr/bin/ntfy /usr/bin/ntfy
USER ntfywui
EXPOSE 8080
ENV NTFYWUI_LISTEN=:8080 \
    NTFYWUI_DATA_DIR=/data \
    NTFYWUI_NTFY_BIN=/usr/bin/ntfy \
    NTFYWUI_NTFY_CONFIG=/etc/ntfy/server.yml \
    NTFYWUI_COOKIE_SECURE=true
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD ["/usr/local/bin/ntfywui", "-healthcheck"]
ENTRYPOINT ["/usr/local/bin/ntfywui"]
