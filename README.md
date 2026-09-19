# WG Agent

WireGuard Agent for remote WireGuard server management via gRPC with mTLS.

## Quick Start

1. Download the certificates for **this node** from the orchestrator and place them in `/etc/wg-agent/`
   (see [Certificates](#certificates)):

```bash
sudo mkdir -p /etc/wg-agent
sudo unzip certs.zip -d /etc/wg-agent
sudo chmod 600 /etc/wg-agent/server.key
```

2. Create the `.env` file:

```bash
cp .env.example .env
```

3. Start with Docker Compose:

```bash
docker compose up -d      # Compose v2 (plugin)
docker-compose up -d      # Compose v1
```

Check that the container actually restarts on reboot — if it was created without a restart
policy, `docker inspect wg-agent --format '{{.HostConfig.RestartPolicy.Name}}'` prints `no`:

```bash
docker update --restart unless-stopped wg-agent
```

## Certificates

The agent authenticates the orchestrator with mTLS. The certificate's `CN` is the node's IP
address, so **every node needs its own pair** — reusing one node's certificate on another
makes the handshake fail.

Download them per node (UI: Servers → node → Download certs):

```
GET /api/servers/{server_id}/nodes/{node_id}/certs
```

The response is a ZIP archive containing:

```
ca.crt        # CA certificate (same for all nodes)
server.crt    # Agent certificate, CN = this node's IP
server.key    # Agent private key (chmod 600)
```

`GET /api/servers/{server_id}/certs` also exists, but it always returns the **primary** node's
certificate. Use it only for single-node servers.

## Manual Docker Run

```bash
docker build -t wg-agent .

docker run -d \
  --name wg-agent \
  --restart unless-stopped \
  --privileged \
  --network host \
  --pid host \
  -v /etc/wireguard:/etc/wireguard \
  -v /etc/wg-agent:/etc/wg-agent:ro \
  -v /etc/dnsmasq.d:/etc/dnsmasq.d \
  -v wg-agent-backups:/var/lib/wg-agent/backups \
  --env-file .env \
  wg-agent
```

`--pid host` and the `/etc/dnsmasq.d` mount are required for the dnsmasq integration:
without them `AGENT_DNSMASQ_CMD_PREFIX=nsenter -t 1 -a --` cannot reach the host namespaces
and the agent never sees `bypass.conf`. Drop both if the integration is unused.

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
| `AGENT_DNSMASQ_BYPASS_CONF` | `` | Path to the dnsmasq bypass config the UI and bot may edit; unset disables the feature |
| `AGENT_DNSMASQ_IPSET_NAME` | `` | ipset flushed after the bypass config changes |
| `AGENT_DNSMASQ_CMD_PREFIX` | `` | Prefix for `systemctl`/`ipset`, e.g. `nsenter -t 1 -a --` to escape the container; needs `pid: host` and `privileged: true` |

Set `AGENT_ALLOWED_INTERFACES` explicitly — usually to the client-facing interface only
(`wg-internal`). Left empty, the agent may rewrite every WireGuard config on the host,
including upstream tunnels whose `PostUp` carries the policy routing.

## Requirements

- Docker with `--privileged` mode (or `--cap-add=NET_ADMIN -v /proc/sys/net:/proc/sys/net`)
- `--network host` for WireGuard interface management
- Access to `/etc/wireguard`
- `--pid host` and `/etc/dnsmasq.d` only for the dnsmasq integration

## Behaviour worth knowing

**The agent makes the config match the database.** Peers added by hand with `wg set` or by
editing the config are removed on the next sync — the orchestrator rewrites the `[Peer]`
sections from its own state. Everything in `[Interface]` (`PostUp`/`PostDown`, `Address`,
`MTU`, `Table`) is per node and preserved.

**Editing the bypass list flushes the ipset.** After the UI or the bot changes
`AGENT_DNSMASQ_BYPASS_CONF`, the agent runs `ipset flush <AGENT_DNSMASQ_IPSET_NAME>` and
restarts dnsmasq. The set stays empty until the domains are resolved again, so until then
their traffic takes the default route instead of the bypass one. Re-resolving the list after
dnsmasq starts fills it back in.

**Applying a config never uses `wg-quick down/up`.** It is done with `wg syncconf`, which
keeps existing connections alive — but `wg syncconf` does not create routes. A peer added
while the interface is up needs its route added separately.
