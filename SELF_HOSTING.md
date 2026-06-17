# Self-hosting LibrePing

This guide covers running your own LibrePing infrastructure end to end: a
**probe** (lend a vantage point), a **hub** (a full node with its own dashboard
that federates with the mesh), putting a hub behind a reverse proxy with a
domain and TLS, opening the ports the peer-to-peer mesh needs, and a complete
reference for every environment variable.

If you just want to monitor a service without hosting anything, you don't need
this — open any public hub's dashboard and add a monitor. See the
[README](README.md).

- [Which one should I run?](#which-one-should-i-run)
- [Required configuration for federation](#required-configuration-for-federation)
- [Running a probe](#running-a-probe)
- [Running a hub](#running-a-hub)
  - [Joining the mesh (required to federate)](#joining-the-mesh-required-to-federate)
  - [Why a hub wants a domain](#why-a-hub-wants-a-domain)
  - [Networking: two separate channels](#networking-two-separate-channels)
  - [Opening the mesh/DHT port](#opening-the-meshdht-port)
  - [Reverse proxy + TLS](#reverse-proxy--tls)
  - [Database and disk](#database-and-disk)
- [Environment variable reference](#environment-variable-reference)
- [Verifying it works](#verifying-it-works)

---

## Which one should I run?

| You want to…                                          | Run a…   |
|-------------------------------------------------------|----------|
| Lend your location to the network, minimal effort     | **Probe** |
| Host your own dashboard and federate with other hubs  | **Hub**   |

A probe needs no domain, no public IP, and no inbound ports — it makes outbound
HTTPS calls to a hub. A hub is a peer in the mesh, so it should be publicly
reachable: ideally a domain with TLS for its HTTP side, and an open TCP port for
the libp2p mesh.

Both ship as Docker images and build from the repo root.

## Required configuration for federation

A hub does **not** join any public bootstrap network on its own — it needs *one*
contact point to enter the mesh, after which the DHT and gossip discover the rest
automatically. There are two ways to give it that contact point:

| Role | Set one of | Without it |
|------|------------|------------|
| **Probe** | `HUB_URL` — base URL of at least one hub to submit to (**required**) | The probe has nowhere to send results; it does nothing. |
| **Hub** | `BOOTSTRAP_SEEDS` (recommended) **or** `BOOTSTRAP_PEERS` | The hub forms an isolated DHT — it advertises to an empty routing table, so two such hubs on the open internet **never** discover each other, no matter how long they run. |

- **`BOOTSTRAP_SEEDS`** (recommended) — comma-separated hub URLs. On startup the
  hub fetches each one's `/api/v1/hubs` + `/api/v1/identity` and dials the live,
  publicly-dialable peers listed there. It's a **self-maintaining** list — new
  hubs appear and dead ones age out without anyone editing a file. The shipped
  `docker-compose.yml` already points at community seeds, so a fresh hub joins
  with zero peering config.
- **`BOOTSTRAP_PEERS`** — an explicit libp2p multiaddr (or several). Use this to
  pin a specific peer, or when you don't want the HTTP seed fetch.

Either way you only need **one** reachable contact; the mesh takes over from
there. See [Joining the mesh](#joining-the-mesh-required-to-federate).

```bash
git clone https://github.com/mwgg/LibrePing.git
cd LibrePing
```

---

## Running a probe

A probe attaches to one or more hubs, runs the checks they assign from your
location, signs each result, and submits it. Results gossip network-wide from
whichever hub it lands on, so a probe contributes to the whole network, not just
"its" hub.

```bash
docker compose -f docker-compose.probe.yml up --build
```

That's the whole thing — it defaults to the public network, auto-detects its
location from its public IP, and offers every check type its host supports. To
customise, copy the short probe env file (one meaningful line, not the full hub
`.env.example`) and edit it:

```bash
cp .env.probe.example .env
docker compose -f docker-compose.probe.yml up --build
```

**A probe is not tied to one hub.** `HUB_URL` is a comma-separated list of seed
hubs, and unless you set `HUB_DISCOVERY=false` the probe also learns other hubs
from the mesh (it reads the current hub's verified directory) and keeps them as
fallbacks. If its hub goes down it fails over automatically and re-homes once
that hub is back. A single seed is enough; listing two gives an instant fallback
before discovery runs:

```bash
HUB_URL=https://nl.lp.mw.gg,https://your-other-hub.example \
  docker compose -f docker-compose.probe.yml up --build
```

Useful knobs (full list in the [reference](#probe)):

- `PROBE_LOCATION="Country,City,lat,lon"` — pin your location instead of the IP
  lookup (e.g. behind a VPN). `PROBE_GEOIP=false` disables the lookup entirely.
- `MAX_CHECKS_PER_MINUTE` — your share of the load. Lower it on a small box.
- `DISABLE_CHECKS=icmp,traceroute` — drop checks your host can't run. ICMP and
  traceroute need the `NET_RAW` capability; the probe auto-detects this and
  simply won't offer them when it's missing.

The probe stores nothing but its identity key (`./data/probe.key`). Keep that
file to keep the same probe identity across restarts.

---

## Running a hub

A hub runs the dashboard, stores results, and gossips with peer hubs. The
default compose brings up four things: the hub backend, a TimescaleDB database,
the dashboard (an nginx container that serves the UI and proxies `/api` to the
hub), and a local probe.

```bash
cp .env.example .env     # then edit — at minimum set PUBLIC_URL (see below)
docker compose up --build
```

- Dashboard: http://localhost:8081
- API: http://localhost:8080
- Mesh (libp2p): TCP 4001

Within a minute the bundled probe reports its first check and a dot appears on
the map. For a real deployment, read the sections below.

### Joining the mesh (required to federate)

A standalone hub works on its own, but to **federate** — to share results,
catalog, subscriptions, alerts, and the hub directory with other hubs — it must
connect to the mesh, and that does not happen from nothing: a LibrePing hub does
**not** bootstrap into any public network. With no contact point its Kademlia DHT
routing table starts empty and stays empty — it advertises the `libreping/v1`
rendezvous to nobody, so **two hubs never pointed at a common peer will never
find each other, even after days.** You only need *one* reachable contact; once
connected, the DHT populates and the hub discovers the rest on its own.

**Recommended — `BOOTSTRAP_SEEDS` (a self-maintaining directory).** Point the hub
at one or more existing hub URLs; on startup it fetches their `/api/v1/hubs` and
`/api/v1/identity` and dials the live peers listed there:

```bash
# in .env — comma-separated hub URLs (the shipped compose already sets these)
BOOTSTRAP_SEEDS=https://nl.lp.mw.gg,https://ca.lp.mw.gg,https://sg.lp.mw.gg
```

Because the directory is gossiped and reachability-verified, the list is always
current — new hubs appear and dead ones age out with no file to edit. If a seed
is down at startup (or every peer later drops), the hub keeps retrying the seeds
while isolated, so it self-heals. Discovered addresses are filtered to public
ranges (unless `HUB_ALLOW_PRIVATE_PEERS`).

**Alternative — `BOOTSTRAP_PEERS` (an explicit multiaddr).** Pin a specific peer
instead of (or in addition to) seeds:

```bash
BOOTSTRAP_PEERS=/ip4/203.0.113.10/tcp/4001/p2p/12D3KooW...thePeerID
```

Get a hub's multiaddr from its startup log — the `p2p mesh listening` line, the
entry with its **public** IP:

```
msg="p2p mesh listening" addrs="[/ip4/127.0.0.1/tcp/4001/p2p/12D3KooW...  /ip4/203.0.113.10/tcp/4001/p2p/12D3KooW...]"
                                                                            ^^^^^^^^^^^^ the public one is what peers dial
```

(`DEFAULT_BOOTSTRAP` is merged with `BOOTSTRAP_PEERS` and exists for baking a
default into an image.)

For any of these to work the peer's mesh port must be reachable — see
[Opening the mesh/DHT port](#opening-the-meshdht-port) — and your own hub should
set `PUBLIC_URL` and a public `P2P_ANNOUNCE_ADDRS` so it is listed (with a
dialable address) in the directory others bootstrap from
([next section](#why-a-hub-wants-a-domain)).

### Why a hub wants a domain

A hub announces itself to the mesh so it shows up in other hubs' directories
(`GET /api/v1/hubs`) and can be used as an entry point. The catch is how that
listing is verified: when a peer receives your signed announcement, it **fetches
`{PUBLIC_URL}/api/v1/identity` and confirms the hub ID served there matches the
signer** before listing you. A valid signature proves authorship, not that a URL
actually serves your hub — so the reachable URL check is what earns you a place
in the directory.

That means a hub that wants to federate needs:

- `ADVERTISE=true` (the default), and
- `PUBLIC_URL` set to a base URL that peers can reach and that serves your hub's
  `/api/`, e.g. `https://hub.example.org`.

A stable domain with TLS is the clean way to provide that. You *can* advertise a
bare `http://<ip>:8080`, but you lose TLS, and IPs are brittle. Probes and the
dashboard work fine without advertising; `PUBLIC_URL` matters specifically for
joining the public directory.

### Networking: two separate channels

This is the part that trips people up. A hub talks over **two independent
channels**, and they are exposed differently:

| Channel | Port (default) | Protocol | Goes through a reverse proxy? |
|---------|----------------|----------|-------------------------------|
| HTTP — dashboard + REST API | 8080 (hub), 8081 (dashboard) | HTTP/JSON | **Yes** — terminate TLS here |
| libp2p mesh — gossip **and DHT peer discovery** | 4001 | raw libp2p TCP stream | **No** — must be reachable directly |

The HTTP side is a normal web app: put it behind nginx/Caddy/Traefik, terminate
TLS, done.

The mesh side is **not HTTP** — it's a libp2p transport carrying both the
gossipsub topics (results, catalog, alerts…) and the Kademlia **DHT** that hubs
use to discover each other. You cannot proxy it through nginx. The libp2p port
(TCP 4001) has to be reachable on its own: open it in your firewall, and if
you're behind NAT, port-forward it and/or announce a dialable address. Without
an open mesh port a hub can still *dial out* to peers, but peers (and the DHT)
can't dial *in*, which limits federation.

### Opening the mesh/DHT port

Peers and the DHT reach you by dialing **inbound TCP 4001**. Open it.

On the host firewall:

```bash
# ufw (Debian/Ubuntu)
sudo ufw allow 4001/tcp

# firewalld (RHEL/Fedora)
sudo firewall-cmd --permanent --add-port=4001/tcp && sudo firewall-cmd --reload

# nftables/iptables
sudo iptables -A INPUT -p tcp --dport 4001 -j ACCEPT
```

On a cloud provider, also allow inbound TCP 4001 in the instance's security
group / network ACL (AWS security group, GCP firewall rule, Hetzner Cloud
firewall, etc.) — the host firewall alone isn't enough there.

Behind a home router / NAT, forward external TCP 4001 to the host, then tell
libp2p which address to advertise (auto-detection can't see your public IP from
inside NAT):

```bash
# in .env — the public address peers should dial
P2P_ANNOUNCE_ADDRS=/ip4/203.0.113.10/tcp/4001
```

If you genuinely can't open a port, set one or more relay multiaddrs and libp2p
will use AutoRelay to stay reachable (less direct, higher latency):

```bash
P2P_RELAYS=/ip4/203.0.113.20/tcp/4001/p2p/12D3KooW...relayPeerID
```

On a LAN of hubs (or for local testing) you can skip all of this and let them
find each other with mDNS: `ENABLE_MDNS=true`.

Confirm the mesh is healthy any time at `GET /api/v1/p2p` — it reports connected
peers, topic peers, DHT routing-table size, and the addresses you're actually
advertising.

### Reverse proxy + TLS

Point your domain at the **dashboard container** (published on `8081` by
default). It serves the SPA and already proxies `/api/` to the hub, so a single
origin covers both the UI and the API — and therefore `PUBLIC_URL` /
`/api/v1/identity` resolves through it.

First, bind the published HTTP ports to localhost so only your reverse proxy can
reach them (the mesh port stays public). In `docker-compose.yml`:

```yaml
  web:
    ports:
      - "127.0.0.1:8081:80"    # dashboard + /api, reverse-proxied
  hub:
    ports:
      - "127.0.0.1:8080:8080"  # optional: direct API, not needed once proxied
      - "4001:4001"            # mesh/DHT — MUST stay publicly reachable
```

**nginx** (`/etc/nginx/sites-available/libreping`, then symlink and reload):

```nginx
server {
    listen 80;
    server_name hub.example.org;
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl http2;
    server_name hub.example.org;

    ssl_certificate     /etc/letsencrypt/live/hub.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/hub.example.org/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }
}
```

Get the certificate with `certbot --nginx -d hub.example.org` (or DNS-01 if the
host isn't reachable on 80). Then set `PUBLIC_URL=https://hub.example.org` in
`.env` and restart the hub.

**Caddy** does TLS automatically — the whole config is two lines:

```caddy
hub.example.org {
    reverse_proxy 127.0.0.1:8081
}
```

**Traefik / other proxies** work the same way: route the domain to the
dashboard's port 80, terminate TLS, forward everything (including `/api/`).
Remember none of this touches port 4001 — that stays open directly.

> The dashboard sets a strict Content-Security-Policy (see `web/nginx.conf`). If
> you change the map tile provider via `VITE_MAP_STYLE` at build time, add its
> origin to the `img-src`/`connect-src` directives there too.

### Database and disk

Set `DATABASE_URL` to a Postgres/TimescaleDB DSN to persist results (the default
compose wires this up for you). **With `DATABASE_URL` unset the hub keeps
everything in memory** — fine for a quick trial, but results are lost on
restart.

By default a hub stores only a capacity-weighted **slice** of the network's
results (`HUB_STORAGE=shards`) and fetches the rest from peers on demand, and it
tiers what it keeps by age so disk stays bounded and flat. To hold a full mirror
instead, set `HUB_STORAGE=archive` — but size it first: see
[Hub disk usage](README.md#hub-disk-usage) for the numbers and tuning.

---

## Environment variable reference

All variables are optional unless noted. Defaults are what you get if you leave
them unset. Booleans accept `true/false/1/0/yes/no/on/off`; durations use Go
syntax (`30s`, `5m`, `2h`). `.env.example` is a ready-to-edit copy of the
hub-side ones.

### Hub — mesh and networking

| Variable | Default | Purpose |
|----------|---------|---------|
| `HTTP_ADDR` | `:8080` | Address the HTTP API/dashboard backend listens on. |
| `P2P_LISTEN` | `/ip4/0.0.0.0/tcp/4001` | libp2p listen multiaddr (the mesh/DHT port). |
| `P2P_ANNOUNCE_ADDRS` | (empty) | Comma-separated public multiaddrs to advertise when auto-detected ones aren't dialable (NAT/containers). |
| `P2P_RELAYS` | (empty) | Comma-separated `/p2p` relay multiaddrs for AutoRelay when direct dialing fails. |
| `BOOTSTRAP_SEEDS` | (empty; compose sets community seeds) | Comma-separated hub URLs whose `/api/v1/hubs` + `/api/v1/identity` supply a live, self-maintaining list of dialable peers. The recommended way to federate. |
| `BOOTSTRAP_PEERS` | (empty) | Comma-separated peer multiaddrs to dial on startup. An explicit alternative to `BOOTSTRAP_SEEDS`; set one or the other (or both) to federate. Get one from a peer's `p2p mesh listening` log line. |
| `DEFAULT_BOOTSTRAP` | (empty) | Fallback bootstrap peers, merged with `BOOTSTRAP_PEERS`. |
| `ENABLE_MDNS` | `false` | Discover peers on the local network via mDNS (LAN/dev). |
| `HUB_ALLOW_PRIVATE_PEERS` | `false` | Allow directory reachability checks to reach private/LAN addresses (SSRF guard off). Only for trusted private federation. |
| `WRITE_RATE_PER_MIN` | `0` | Per-IP rate limit on write endpoints (create check/subscription/alert, probe register). `0` = sane default, negative = disabled. |

### Hub — advertisement and directory

| Variable | Default | Purpose |
|----------|---------|---------|
| `ADVERTISE` | `true` | Gossip a signed announcement so this hub appears in others' directories. |
| `PUBLIC_URL` | (empty) | This hub's public base URL. **Required to advertise** — peers fetch `{PUBLIC_URL}/api/v1/identity` to verify before listing. |
| `HUB_NAME` | (empty) | Friendly name shown in directories / on the map. |
| `HUB_LOCATION` | (auto) | `"Country,City,lat,lon"` to override the IP-based location. Self-declared; no proof-of-location. |
| `HUB_GEOIP` | `true` | Auto-detect location from the public IP when `HUB_LOCATION` is unset. |
| `ADVERTISE_INTERVAL` | `1m` | How often to re-gossip this hub's announcement. |

### Hub — trust policy

| Variable | Default | Purpose |
|----------|---------|---------|
| `TRUST_POLICY` | `open` | `open` accepts any validly-signed result (tagged by origin, trust via corroboration); `allowlist` accepts only listed node IDs. Signature verification is always enforced regardless. |
| `TRUST_ALLOWLIST` | (empty) | Comma-separated probe/hub node IDs accepted when `TRUST_POLICY=allowlist`. |

### Hub — storage role and result tiers

| Variable | Default | Purpose |
|----------|---------|---------|
| `HUB_STORAGE` | `shards` | `shards` = capacity-weighted slice + fetch rest on demand; `archive` = full mirror; `none` = store only your own pins. |
| `HUB_STORAGE_CAPACITY` | `1` | Relative weight for shard placement (higher = larger share). Ignored for `archive`/`none`. |
| `RESULT_COMPRESS_AFTER_DAYS` | `2` | Compress raw results older than this (`0` = no compression). |
| `RESULT_RETENTION_DAYS` | `7` | Keep full per-result detail this long, then drop raw (hourly rollups carry the summary). |
| `RESULT_HOURLY_RETENTION_DAYS` | `90` | Keep hourly summaries this long. |
| `RESULT_DAILY_RETENTION_DAYS` | `730` | Keep daily summaries this long. `0` on any tier = keep forever. |
| `DATABASE_URL` | (unset → in-memory) | Postgres/TimescaleDB DSN. Unset means results live in memory only and are lost on restart. |

### Hub — check distribution

| Variable | Default | Purpose |
|----------|---------|---------|
| `TARGET_REDUNDANCY` | `3` | How many probes each hub tries to assign per check (corroboration target). |
| `SEED_CHECK_TARGET` | (empty) | Optional URL to seed one HTTP check on first boot so a fresh network isn't empty. |

### Hub — alerts

Alert channels (ntfy, Discord, Slack, raw webhook) are all plain outbound HTTPS
to an owner-supplied, end-to-end-sealed destination, so they need **no
hub-operator configuration** — there is nothing to set up to enable them.

| Variable | Default | Purpose |
|----------|---------|---------|
| `ALERT_INTERVAL` | `30s` | How often the engine evaluates rules it is responsible for. |
| `ALERT_HUB_TTL` | `3m` | How long a responsible hub may be silent before a peer takes over its alerts (failover window). |
| `ALERT_WEBHOOK_ALLOW_HTTP` | `false` | Allow plain-http alert destinations across all channels (otherwise https-only, no private/metadata ranges). |

### Hub — advanced / rarely changed

| Variable | Default | Purpose |
|----------|---------|---------|
| `HUB_KEY_PATH` | `./data/hub.key` | Ed25519 identity key file. Keep it to keep the same hub ID (and libp2p PeerID). |
| `MIGRATIONS_DIR` | `./migrations` | Directory of SQL migrations applied on startup. |
| `CATALOG_GOSSIP_INTERVAL` | `1m` | Anti-entropy re-broadcast interval for catalog/subscriptions/alerts. |
| `INTEREST_INTERVAL` | `30s` | How often the hub recomputes which shards it should hold. |

### Probe

| Variable | Default | Purpose |
|----------|---------|---------|
| `HUB_URL` | (required) | Comma-separated base URLs of seed hubs to submit to. The probe fails over between them. |
| `HUB_DISCOVERY` | `true` | Also learn additional hubs from the mesh directory for failover. Set `false` to use only the configured list. |
| `POLL_INTERVAL` | `60s` | How often the probe re-registers (heartbeat) and refreshes its assignment. |
| `MAX_CHECKS_PER_MINUTE` | `300` | Hard cap on checks this probe runs per minute (`0` = unlimited). A network-wide cost dial; hubs clamp declared capacity at 600. |
| `DISABLE_CHECKS` | (empty) | Comma-separated check types to refuse (e.g. `icmp,traceroute`). |
| `PROBE_LOCATION` | (auto) | `"Country,City,lat,lon"` to override the IP-based location. |
| `PROBE_GEOIP` | `true` | Auto-detect location from the public IP when `PROBE_LOCATION` is unset. |
| `PROBE_BLOCK_PRIVATE` | `true` | Block check targets resolving to private/loopback/link-local/metadata ranges (SSRF guard). |
| `PROBE_ALLOW_TARGETS` | (empty) | Comma-separated CIDRs allowed as targets even when `PROBE_BLOCK_PRIVATE` is on. E.g. `10.0.0.0/8,192.168.1.0/24`. |
| `PROBE_KEY_PATH` | `./data/probe.key` | Ed25519 identity key file. Keep it to keep the same probe ID. |

---

## Verifying it works

- **Hub started, mesh listening.** The hub logs `p2p mesh listening addrs=[...]`
  on startup — that multiaddr is what you hand to a peer as its
  `BOOTSTRAP_PEERS`.
- **Mesh/DHT health.** `curl https://hub.example.org/api/v1/p2p` shows connected
  peers, topic peers, DHT table size, and your advertised addresses. If peers
  stay at 0 and you expected federation, recheck the [mesh port](#opening-the-meshdht-port).
- **Directory listing.** Once advertising and reachable, your hub appears in
  peers' `GET /api/v1/hubs`, and `curl https://hub.example.org/api/v1/identity`
  returns your `hub_id` (this is exactly what peers verify).
- **Dashboard.** Open your domain; the world map loads and the bundled probe's
  first results appear within a minute.
- **Probe failover.** Point a probe at your hub, then stop the hub: the probe
  logs a failover to another hub and keeps running; restart the hub and it
  re-homes on the next poll.
