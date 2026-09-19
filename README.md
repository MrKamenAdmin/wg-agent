# WG Agent

English | [Русский](README.ru.md)

An agent that connects your WireGuard server to the **[panel.brekhin.me](https://panel.brekhin.me)** panel.

The panel manages clients (peers): it creates them, hands out `.conf` files and QR codes, disables them on a timer, accounts traffic and takes backups. The agent is a small gRPC service on your server and the only thing that touches WireGuard — the panel never runs `wg` itself, it goes through the agent.

> The panel's interface is in Russian. Button names are quoted below in Russian with a translation, so you can find them on screen.

```
 panel.brekhin.me                         your server
┌────────────────┐   gRPC + mTLS :9090   ┌──────────────┐     ┌─────────────────────────┐
│  panel (API,   │ ────────────────────▶ │   wg-agent   │ ──▶ │ wg / wg-quick           │
│  peer DB, UI)  │                       │  (Docker)    │     │ /etc/wireguard/wg0.conf │
└────────────────┘                       └──────────────┘     └─────────────────────────┘
                                                                        ▲  UDP :51820
                                                                 WireGuard clients
```

## Contents

- [How it works](#how-it-works)
- [What you trust the panel with](#what-you-trust-the-panel-with)
- [Requirements](#requirements)
- [Step 1. WireGuard on the server](#step-1-wireguard-on-the-server)
- [Step 2. A panel account](#step-2-a-panel-account)
- [Step 3. The server in the panel, and certificates](#step-3-the-server-in-the-panel-and-certificates)
- [Step 4. Installing the agent](#step-4-installing-the-agent)
- [Step 5. Firewall](#step-5-firewall)
- [Step 6. Checking the connection and first clients](#step-6-checking-the-connection-and-first-clients)
- [Several nodes behind one server](#several-nodes-behind-one-server)
- [dnsmasq bypass list (optional)](#dnsmasq-bypass-list-optional)
- [Environment variables](#environment-variables)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## How it works

- The agent listens on TCP port `9090` and only accepts a client whose certificate is signed by the panel's CA (mTLS). Without that certificate there is no way in.
- The peer list lives in the panel. On every change the panel rewrites the `[Peer]` sections of `/etc/wireguard/wg0.conf` and applies them with `wg syncconf`, so clients that are already connected stay connected.
- The `[Interface]` section (address, `PostUp`/`PostDown`, MTU) stays yours: the panel reads it but never changes it while syncing.
- A disabled peer is not removed from the file, it is commented out (`# DISABLED`), so the history survives.
- Before every config write the agent stores a backup in `/var/lib/wg-agent/backups`. Backups older than `AGENT_BACKUP_RETENTION_DAYS` (7 days by default) are deleted automatically.

## What you trust the panel with

Read this before installing. By connecting a server you give the panel's owner:

- **read and write access** to `/etc/wireguard/<interface>.conf`, including the interface's **private key**;
- the right to decide who may connect to your VPN (create, disable and delete peers);
- an interface restart through `wg-quick down/up` when a backup is restored. Commands in `PostUp`/`PostDown` run as root, so whoever controls the agent **effectively has root on the host**;
- with the bypass list enabled: writing `bypass.conf`, plus `systemctl restart dnsmasq` and `ipset flush` on the host.

The container runs with `privileged: true`, `network_mode: host` and `pid: host`, because otherwise it cannot manage the host's interface. Only connect a server you are willing to share on those terms. You can limit the agent to a single interface with `AGENT_ALLOWED_INTERFACES` (see below).

## Requirements

- A Linux server with a public IPv4 address (the instructions below are written for Debian/Ubuntu).
- Docker and Docker Compose v2: `curl -fsSL https://get.docker.com | sh`.
- Open ports: UDP `51820` for clients and TCP `9090` for the panel.
- Root or `sudo`.

## Step 1. WireGuard on the server

> If WireGuard is already running and has clients, go to step 2. Step 6 shows how to import the existing clients into the panel.

Install WireGuard and generate the server keys:

```bash
sudo apt update && sudo apt install -y wireguard
sudo sh -c 'umask 077; wg genkey > /etc/wireguard/server.key; wg pubkey < /etc/wireguard/server.key > /etc/wireguard/server.pub'
```

Find the external network interface (usually `eth0` or `ens3`):

```bash
ip route show default | awk '{print $5}'
```

Create `/etc/wireguard/wg0.conf`. Substitute the private key (`sudo cat /etc/wireguard/server.key`) and your own external interface instead of `eth0`:

```ini
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = <server private key>
PostUp = iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE; iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT
```

Enable routing and bring the interface up:

```bash
echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-wireguard.conf
sudo sysctl --system
sudo chmod 600 /etc/wireguard/wg0.conf
sudo systemctl enable --now wg-quick@wg0
sudo wg show wg0          # should print interface: wg0 and listening port: 51820
```

## Step 2. A panel account

There is no self-service registration: accounts are issued by the administrator. Adding your own servers needs the **moderator** role. Write to the repository owner ([@MrKamenAdmin](https://github.com/MrKamenAdmin)) and sign in at [panel.brekhin.me](https://panel.brekhin.me) with the credentials you get.

## Step 3. The server in the panel, and certificates

In the panel open **«Администрирование» → «Серверы» → «Добавить сервер WireGuard»** (Administration → Servers → Add WireGuard server) and fill in the form:

| Field | What to enter | Example |
|-------|---------------|---------|
| Название сервера (server name) | Any name; only panel users see it | `Frankfurt` |
| Адрес агента (agent address) | `<server IP or domain>:9090` — where the panel will reach the agent | `203.0.113.10:9090` |
| Публичный ключ (public key) | Output of `sudo cat /etc/wireguard/server.pub` | `kJXi…NXc=` |
| Эндпоинт (endpoint) | `<IP or domain>:51820`, goes into the client configs | `vpn.example.com:51820` |
| Имя интерфейса (interface name) | The config name without `.conf` | `wg0` |
| IP пул CIDR (IP pool CIDR) | The subnet from `Address` in `wg0.conf`; client addresses come from it | `10.8.0.0/24` |
| Исключить из IP пула (exclude from pool) | The server's own address and any other taken ones | `10.8.0.1` |
| DNS для клиентов (client DNS) | The DNS clients will receive | `1.1.1.1` |
| AllowedIPs для клиентов (client AllowedIPs) | `0.0.0.0/0` sends all client traffic through the VPN; a subnet sends only that | `0.0.0.0/0` |
| IPv6 | Enable only if IPv6 is configured for `wg0` on the server | — |

> **The agent address matters.** The agent's certificate is issued for exactly that IP or domain. If you change the address later, download the certificates again, otherwise the panel gets `x509: certificate is valid for …`.

After saving, the panel offers **«Скачать сертификаты и закрыть»** (Download certificates and close). Keep `agent-certs.zip`: it holds `ca.crt`, `server.crt` and `server.key`. You can download the archive later with the "Скачать сертификаты агента" (download agent certificates) icon on the server's node.

Copy the archive to the server:

```bash
scp agent-certs.zip root@203.0.113.10:/root/
```

## Step 4. Installing the agent

Put the certificates in place on the server:

```bash
sudo apt install -y unzip git
sudo mkdir -p /etc/wg-agent
sudo unzip -o /root/agent-certs.zip -d /etc/wg-agent
sudo chmod 600 /etc/wg-agent/server.key
```

Fetch the agent and prepare `.env`:

```bash
git clone https://github.com/MrKamenAdmin/wg-agent.git
cd wg-agent
cp .env.example .env
sed -i 's/^AGENT_ALLOWED_INTERFACES=.*/AGENT_ALLOWED_INTERFACES=wg0/' .env   # the agent will only see wg0
```

Build and start it:

```bash
sudo docker compose up -d --build
sudo docker compose logs -f
```

This line should appear in the logs:

```
gRPC server listening on :9090 (mTLS enabled)
```

<details>
<summary>Without Docker Compose</summary>

```bash
sudo docker build -t wg-agent .
sudo docker run -d \
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

`--pid host` and the `/etc/dnsmasq.d` mount are only needed for the bypass list: without them
`nsenter` from `AGENT_DNSMASQ_CMD_PREFIX` cannot enter the host namespaces and the agent cannot
see `bypass.conf`. If you do not use the bypass list, drop both lines.

</details>

## Step 5. Firewall

Clients need UDP `51820`, while the agent's port `9090` is better opened for the panel alone. mTLS already keeps strangers out, but there is no reason to leave extra attack surface. Ask the administrator which IP the panel connects from.

```bash
sudo ufw allow OpenSSH
sudo ufw allow 51820/udp
sudo ufw allow from <panel IP> to any port 9090 proto tcp
sudo ufw enable
```

The agent runs in the host's network namespace (`network_mode: host`), so `ufw` rules apply to it as usual.

## Step 6. Checking the connection and first clients

1. In the panel press **«Проверить соединение»** (test connection) on the server. The node card should show `Agent v1.0.0 on <hostname>`.
2. **If the server already had clients**, open **«Панель» → «Импорт из конфига»** (Dashboard → Import from config). Peers from `wg0.conf` appear in the panel with their `AllowedIPs`, `Endpoint` and `PersistentKeepalive` preserved.
   > Import reconciles the panel with the config: peers that exist in the panel but are missing from `wg0.conf` **are deleted from the panel**. Import right after connecting, before you create any clients through the panel.
3. Open **«Пиры» → «Добавить пир»** (Peers → Add peer), then download the `.conf` or show the client a QR code.
4. Check on the server: `sudo wg show wg0`. The new peer should appear without restarting the interface.

## Several nodes behind one server

One "server" in the panel can be served by several machines carrying an identical peer set. The client gets a single config whose `Endpoint` is a domain with A-records pointing at every node.

- Every node must carry the **same `PrivateKey` and `ListenPort`** in `[Interface]`, otherwise clients cannot connect to the "other" node. Everything else (`Address`, `PostUp`, MTU) is per node.
- In the panel: server → **«Добавить ноду»** (add node) → agent address `host:9090`, interface, public IP. Then download the certificates **for that node** and install the agent as in step 4.
- Press **«Проверить ноду»** (check node): the panel compares the key and the port with the server's.
- Peer changes propagate to every node. If a node was unreachable, the panel catches it up on its own within a couple of minutes, or you can press **«Пересинхронизировать конфиг»** (re-sync config).

## dnsmasq bypass list (optional)

If dnsmasq on the server fills an ipset from a domain list (`ipset=/domain/bypass_vpn`), the panel can edit that list. Add to `.env`:

```bash
AGENT_DNSMASQ_BYPASS_CONF=/etc/dnsmasq.d/bypass.conf
AGENT_DNSMASQ_IPSET_NAME=bypass_vpn
AGENT_DNSMASQ_CMD_PREFIX=nsenter -t 1 -a --
```

The `bypass.conf` file has to exist already. `docker-compose.yml` mounts `/etc/dnsmasq.d` and sets `pid: host`, so `systemctl` and `ipset` run in the host namespaces through `nsenter`. With the variables unset the feature is off.

> After every edit from the panel the agent runs `ipset flush` and restarts dnsmasq. The set stays empty until the domains resolve again, and until then their traffic takes the normal route rather than the bypass.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENT_GRPC_PORT` | `9090` | gRPC port. If you change it, use the same port in the agent address in the panel |
| `AGENT_TLS_CERT` | `/etc/wg-agent/server.crt` | The agent's certificate |
| `AGENT_TLS_KEY` | `/etc/wg-agent/server.key` | The agent's private key (`chmod 600`) |
| `AGENT_TLS_CA` | `/etc/wg-agent/ca.crt` | The panel's CA, used to verify the client certificate |
| `AGENT_WG_CONFIG_DIR` | `/etc/wireguard` | WireGuard config directory |
| `AGENT_BACKUP_DIR` | `/var/lib/wg-agent/backups` | Backup directory |
| `AGENT_ALLOWED_INTERFACES` | empty (all) | Comma-separated interfaces the agent may touch. `wg0` is recommended |
| `AGENT_BACKUP_RETENTION_DAYS` | `7` | After how many days backups are deleted |
| `AGENT_DNSMASQ_BYPASS_CONF` | empty (off) | Path to `bypass.conf` |
| `AGENT_DNSMASQ_IPSET_NAME` | `bypass_vpn` | Name of the ipset to flush |
| `AGENT_DNSMASQ_CMD_PREFIX` | empty | Prefix for `systemctl`/`ipset`, e.g. `nsenter -t 1 -a --` |

## Maintenance

**Updating the agent**

```bash
cd wg-agent
git pull
sudo docker compose up -d --build
```

**Renewing the certificate.** The agent's certificate is valid for 3 years. The panel warns the
administrators in Telegram ahead of time and shows the date on the node card; its own client
certificate it renews by itself, without your involvement. To check the date on the server:

```bash
sudo openssl x509 -enddate -noout -in /etc/wg-agent/server.crt
```

To renew, download a fresh archive in the panel (the "Скачать сертификаты агента" icon on the node), unpack it into `/etc/wg-agent` as in step 4 and run `sudo docker compose restart`.

**Backups** live in the `wg-agent-backups` Docker volume. In the panel you can view, download and restore them on the **«Бэкапы»** (Backups) page.

**Disconnecting from the panel.** Stop the agent first, then delete the server in the panel:

```bash
sudo docker compose down        # add -v to drop the backups as well
```

WireGuard keeps running with the last config that was written.

## Troubleshooting

| Symptom | Cause and fix |
|---------|---------------|
| The agent exits with `failed to load server cert` or `TLS … file not found` | The files are missing from `/etc/wg-agent` or their permissions are wrong. Check `ls -l /etc/wg-agent`: it must hold `ca.crt`, `server.crt`, `server.key` |
| `WireGuard config dir not found` | There is no `/etc/wireguard` on the host. Do step 1 |
| Panel: `connection refused` or a timeout | The agent is not running (`docker compose ps`), port `9090` is blocked by a firewall or the provider, or the agent address in the panel is wrong |
| Panel: `x509: certificate is valid for X, not Y` | The agent address in the panel differs from the one the certificate was issued for. Download the certificates again and restart the agent |
| Panel: `interface wg0 is not in allowed list` | The interface is not listed in `AGENT_ALLOWED_INTERFACES` |
| Panel: `syncconf failed` | Something is wrong in `wg0.conf`. Check `sudo wg-quick strip wg0` and `sudo wg show wg0` |
| The node is marked out of sync in the panel | The panel retries on its own every minute. The reason is shown on the node card; to retry at once press "Пересинхронизировать конфиг" |

Agent logs: `sudo docker compose logs -f wg-agent`.

## License

MIT, full text in [LICENSE](LICENSE).
