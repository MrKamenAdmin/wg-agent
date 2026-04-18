# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

# Copy go.mod and go.sum first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the agent binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /wg-agent ./cmd/agent

# Runtime stage
FROM alpine:3.19

# Install WireGuard tools and dependencies for wg-quick.
# util-linux supplies `nsenter`, which the agent uses to run systemctl/ipset
# in the host's namespaces when running under docker with pid:host.
RUN apk add --no-cache wireguard-tools bash iproute2 iptables ipset util-linux

# Create directories
RUN mkdir -p /etc/wg-agent /var/lib/wg-agent/backups

# Copy binary
COPY --from=builder /wg-agent /usr/local/bin/wg-agent

# Set permissions
RUN chmod +x /usr/local/bin/wg-agent

# Environment variables (to be overridden)
ENV AGENT_GRPC_PORT=9090
ENV AGENT_WG_CONFIG_DIR=/etc/wireguard
ENV AGENT_BACKUP_DIR=/var/lib/wg-agent/backups
ENV AGENT_TLS_CERT=/etc/wg-agent/server.crt
ENV AGENT_TLS_KEY=/etc/wg-agent/server.key
ENV AGENT_TLS_CA=/etc/wg-agent/ca.crt

# Expose gRPC port
EXPOSE 9090

# Required capabilities for WireGuard
# Run with: --privileged or --cap-add=NET_ADMIN -v /proc/sys/net:/proc/sys/net

ENTRYPOINT ["/usr/local/bin/wg-agent"]
