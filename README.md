# WG Agent

WireGuard Agent for remote WireGuard server management via gRPC with mTLS.

## Quick Start

1. Copy certificates from the orchestrator:
```bash
mkdir -p certs
# Copy ca.crt, server.crt, server.key from orchestrator
```

2. Create `.env` file:
```bash
cp .env.example .env
```

3. Start with Docker Compose:
```bash
docker compose up -d
```

## Manual Docker Run

```bash
docker build -t wg-agent .

docker run -d \
  --name wg-agent \
  --restart unless-stopped \
  --privileged \
  --network host \
  -v /etc/wireguard:/etc/wireguard \
  -v $(pwd)/certs:/etc/wg-agent:ro \
  -v wg-agent-backups:/var/lib/wg-agent/backups \
  --env-file .env \
  wg-agent
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_GRPC_PORT` | `9090` | gRPC server port |
| `AGENT_TLS_CERT` | `/etc/wg-agent/server.crt` | Server certificate path |
| `AGENT_TLS_KEY` | `/etc/wg-agent/server.key` | Server private key path |
| `AGENT_TLS_CA` | `/etc/wg-agent/ca.crt` | CA certificate for client verification |
| `AGENT_WG_CONFIG_DIR` | `/etc/wireguard` | WireGuard config directory |
| `AGENT_BACKUP_DIR` | `/var/lib/wg-agent/backups` | Backup storage directory |
| `AGENT_ALLOWED_INTERFACES` | `` | Comma-separated list of allowed interfaces (empty = all) |
| `AGENT_BACKUP_RETENTION_DAYS` | `7` | Days to keep backups |

## Requirements

- Docker with `--privileged` mode (or `--cap-add=NET_ADMIN -v /proc/sys/net:/proc/sys/net`)
- `--network host` for WireGuard interface management
- Access to `/etc/wireguard` directory

## Certificate Setup

The agent requires mTLS certificates. Generate them on the orchestrator and copy to the agent:

```
certs/
├── ca.crt        # CA certificate (same as orchestrator)
├── server.crt    # Agent server certificate
└── server.key    # Agent server private key
```
