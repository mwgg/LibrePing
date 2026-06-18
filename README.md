<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="web/public/logo-dark.svg">
    <img src="web/public/logo.svg" alt="LibrePing" width="88" height="88">
  </picture>
</p>

<h1 align="center">LibrePing</h1>

<p align="center">
  <b>Open-source, decentralized uptime monitoring — from everywhere, owned by no one.</b>
</p>

<p align="center">
  <b>Try it now: <a href="https://nl.lp.mw.gg">nl.lp.mw.gg</a></b> — no signup.
  More public hubs in the <a href="https://github.com/mwgg/LibrePing/wiki/Public-hubs">wiki</a>.
</p>

<p align="center">
  <a href="https://nl.lp.mw.gg"><img src="https://nl.lp.mw.gg/api/v1/network/banner.svg" alt="LibrePing live network — hubs, probes, countries" width="620"></a>
</p>

LibrePing checks whether websites and services are online, **from many places
around the world at once**, and shows the results on a live map. Unlike
commercial monitoring services, there is **no central company and no single
server**: anyone can run a node, and nodes share their measurements with each
other directly.

You can use LibrePing to:

- **Watch your own services** from multiple countries — catch outages that only
  affect some regions.
- **Contribute a vantage point** — if you have a spare server, VPS, or NAS, run
  a probe and help monitor popular services from your location.
- **Run your own hub** — host a full node with its own dashboard that federates
  with the wider LibrePing mesh.

> Think of it as a community-run [globalping](https://globalping.io), combining
> many kinds of checks (HTTP, TCP, DNS, TLS certificates, ping, traceroute) that
> run automatically — and it's completely open source.

## Features

- **Multi-location checks** — HTTP(S), TCP, DNS, TLS certificate, ICMP ping,
  and traceroute, run from probes around the world.
- **Truly decentralized** — hubs form a peer-to-peer [libp2p](https://libp2p.io)
  gossip mesh with no central server. Results, the check catalog, and the hub
  directory all federate and *eventually converge* — gossip is backed by
  anti-entropy and a catch-up sync, so a hub that joins late or briefly drops
  out pulls the recent history it missed instead of only seeing new traffic.
- **No signup** — the dashboard creates a key in your browser that *is* your
  account. Bookmark your dashboard link, keep a recovery phrase, done.
- **Deduplicated by design** — the same target added by many people is *one*
  check, monitored once and shared, so the network isn't doing redundant work.
- **Fair, capped load** — each hub spreads checks across its probes toward a
  redundancy target, and no probe exceeds its `MAX_CHECKS_PER_MINUTE`.
- **Everything is signed and verified** — every result, check, subscription,
  and hub announcement carries a cryptographic signature that *every* hub checks;
  forged or tampered data is dropped on arrival.
- **Encrypted alerts** — get notified via **ntfy, Discord, Slack, or a raw
  webhook** when a service is down, confirmed from multiple locations. Every
  channel is a plain HTTPS push (no hub SMTP/config needed). Your destination is
  **sealed** so only the few hubs that actually notify you can read it — not the
  rest of the network. Add, bulk-apply, and delete rules right from the dashboard.
- **Reliable delivery** — alerts are **at-least-once**: a failed send is
  retried (never silently dropped), and if the notifying hub goes offline another
  hub **automatically takes over**.
- **Resilient probes** — a probe isn't tied to one hub. It learns other hubs
  from the mesh and **fails over automatically** if its current hub goes down,
  re-homing once it's back — so no single hub outage takes a vantage point
  offline.
- **Live geographic dashboard** — a world map of where your service is
  reachable from, a network **overview** (monitor health, probes, hubs, shard
  coverage), and a **per-monitor view** with an uptime/latency timeline,
  per-location breakdown, and recent checks.
- **Automatic location** — probes and hubs detect their own location from their
  public IP (free, key-less geolocation with provider fallback), so the map is
  accurate with zero configuration. Still overridable, and still self-declared —
  there's no proof-of-location.
- **Scales with the network** — results are **sharded** across hubs rather than
  every hub mirroring everything, so the mesh can grow without each node carrying
  the whole load. Small meshes still keep everything automatically.

---

## How it works (in one picture)

```
 Probe (Frankfurt) ─┐
 Probe (Tokyo)     ─┼─▶  Your Hub  ◀──gossip──▶  Someone else's Hub  ◀──▶ ...
 Probe (New York)  ─┘    (+ map)                  (+ map)
```

- **Probes** run the actual checks and **cryptographically sign** every result.
- **Hubs** collect results, show them on a map, and **gossip** them — along with
  the check catalog, your subscriptions, alert rules, and announcements of other
  public hubs — across a peer-to-peer network. Every hub independently verifies
  the signature on everything it receives, so nobody can fake a measurement or
  tamper with a check.

**You contribute to the whole network, not to one hub.** The control plane —
the check catalog, your subscriptions, alert rules, and the hub directory — is
**fully replicated** to every hub, while the heavier result stream is **sharded**
across hubs (each result is held by a few of them, not all). A hub serves any
result it doesn't hold by fetching it from the shard's holders on demand, so
every hub still presents the same global picture. Any hub is just your entry
point — pick one, or run your own, and it converges (gossip + anti-entropy +
catch-up sync; convergence is eventual, not instantaneous, and a hub must be
network-reachable to participate — see `P2P_ANNOUNCE_ADDRS` below if yours is
behind NAT).

There are two things you can run. Pick one:

| You want to…                                   | Run this        |
|------------------------------------------------|-----------------|
| Host your own dashboard + join the mesh        | a **Hub**       |
| Just lend your location to the network         | a **Probe**     |

---

## Just want to monitor your service? (no hosting, no signup)

Open a public hub's dashboard — e.g. **https://nl.lp.mw.gg** — click
**Monitor it**, and paste your URL. That's the whole flow:

- No account. The dashboard creates a key in your browser that *is* your
  identity; your services live under it. Bookmark the **dashboard link** from the
  Account panel to come back (or from any device), and save the **recovery
  phrase** to move it to another device.
- Probes across the network start checking your service from many locations.
- Add an **alert** (ntfy, Discord, Slack, or a raw webhook) to get notified when
  it goes down, confirmed from multiple locations. Your destination is
  **encrypted** so only the handful of hubs that actually notify you can read it
  — not the whole network. Delivery is reliable: failed sends are retried, and if
  the notifying hub goes offline another takes over, so you don't miss an outage.

Because everything is shared, the *same* monitor is bookmarkable from any hub.
The rest of this guide is for people who want to run infrastructure.

### Webhook alert payload

The **ntfy / Discord / Slack** channels send a ready-made human-readable message.
The **raw webhook** channel `POST`s this JSON (the responsible hub is the sender;
your sealed destination is never echoed in the body):

```json
{
  "check_id": "fcc615b0bb0478d6",
  "target": "http://example.org:8137",
  "status": "down",
  "at_ms": 1781782635219,
  "locations": [
    {
      "check_id": "fcc615b0bb0478d6",
      "check_type": "http",
      "target": "http://example.org:8137",
      "probe_id": "e66e72da7a3bd07155b099f6dd8952fd",
      "location": { "country": "Russia", "city": "Moscow", "lat": 55.75, "lon": 37.62 },
      "timestamp_ms": 1781782630927,
      "status": "down",
      "rtt_ms": 40.309,
      "detail": { "error": "dial tcp …: connect: connection refused" }
    }
  ]
}
```

| Field | Meaning |
|-------|---------|
| `check_id` | Content-addressed ID of the monitored check. |
| `target` | What's monitored (URL / host:port / hostname). |
| `status` | The new overall status that triggered the notification: `down`, `up` (recovery), or `degraded`. |
| `at_ms` | When the notification was generated (epoch ms). |
| `locations[]` | The latest per-probe result from each reporting location (mixed up/down during a transition). Each has `probe_id`, `location` (country/city/lat/lon), `status`, `rtt_ms`, `timestamp_ms`, and a `detail` map (`error` when down, `status_code` when up). |

A `2xx` response is treated as delivered; anything else is retried.

## Quick start (run infrastructure)

You need [Docker](https://docs.docker.com/get-docker/) installed. That's it.

> For the full walkthrough — putting a hub behind nginx/Caddy with a domain and
> TLS, opening the libp2p mesh/DHT port, and a reference for **every** `.env`
> option — see **[SELF_HOSTING.md](./SELF_HOSTING.md)**. The quick
> start below gets you running locally.

### Option A — Run a full Hub (dashboard + database + a local probe)

```bash
git clone https://github.com/mwgg/LibrePing.git
cd LibrePing
docker compose up --build
```

Then open **http://localhost:8081** in your browser. You'll see the world map;
within a minute the local probe reports its first check and a dot appears.

- Dashboard: http://localhost:8081
- API: http://localhost:8080

To **federate with other hubs** a hub needs one contact point into the mesh; the
shipped `docker-compose.yml` already sets `BOOTSTRAP_SEEDS` to community hubs, so
a fresh hub **auto-joins** — it fetches a live, self-maintaining peer list from
those seeds' `/api/v1/hubs` and dials in. To pin specific peers instead, set
`BOOTSTRAP_PEERS` in a `.env` file (copy `.env.example` first); your hub prints
its own address on startup (look for `p2p mesh listening`). Once connected to at
least one peer, hubs also discover each other through the DHT over time. A hub
with `PUBLIC_URL` (and a public `P2P_ANNOUNCE_ADDRS`) advertises itself so it
shows up — with a dialable address — in other hubs' directories
(`GET /api/v1/hubs`). For this to work your libp2p port (TCP **4001** by default)
must be reachable; behind NAT, set `P2P_ANNOUNCE_ADDRS` (and/or a relay via
`P2P_RELAYS`), or use `ENABLE_MDNS=true` on a LAN. Check mesh health any time at
`GET /api/v1/p2p` (connected peers, topic peers, DHT table size, advertised
addrs). For a production hub with a domain + TLS and the exact firewall commands
to open the mesh/DHT port, follow
[SELF_HOSTING.md](./SELF_HOSTING.md).

**Add a monitor.** A monitor is two signed steps: create the shared,
content-addressed *check*, then add an owner-signed *subscription* that links
your browser key to it. A check is only assigned to probes while it has at least
one live subscription, so `POST /api/v1/checks` **alone creates a catalog entry
that is not yet monitored** — the dashboard does both for you. From the API:

```bash
# 1. Create (or dedupe to) the shared check; returns its content-derived id.
curl -X POST http://localhost:8080/api/v1/checks \
  -H 'content-type: application/json' \
  -d '{"type":"http","target":"https://your-service.example","interval_seconds":60}'

# 2. Subscribe to that check id with an owner-signed Subscription so it actually
#    gets monitored. The subscription is signed by a browser-held key (see
#    web/src/identity.ts); the easiest path is to add the monitor from the
#    dashboard, which signs and submits both steps.
```

### Option B — Run a Probe only (lend your location to the network)

A probe joins the network through any hub as its entry point — your
measurements gossip out to every hub from there. It needs no configuration: it
defaults to the public network, so this is the whole thing:

```bash
git clone https://github.com/mwgg/LibrePing.git
cd LibrePing
docker compose -f docker-compose.probe.yml up --build
```

To point it at your own hub or set a location, copy the short probe env file
(`cp .env.probe.example .env`, then edit) — it's one meaningful line, unlike the
full hub `.env.example`. Or just pass `HUB_URL` inline:

```bash
HUB_URL=https://your-hub.example \
  docker compose -f docker-compose.probe.yml up --build
```

**A probe is never tied to a single hub.** `HUB_URL` is a comma-separated list
of seed hubs, and unless you set `HUB_DISCOVERY=false` the probe also **learns
other hubs from the mesh** (it reads the entry hub's verified directory) and
keeps them as fallbacks. If its current hub goes down, the probe automatically
**fails over to another** and keeps running — register, fetch its check
assignment, and submit results there — then **re-homes** to your configured hub
once it is reachable again. A result that can't be delivered to the current hub
is retried on the next healthy one rather than dropped; since results gossip
network-wide, it reaches your home hub either way. So a single entry point is
enough to be resilient, and listing a couple of hubs gives an immediate fallback
even before discovery kicks in:

```bash
HUB_URL=https://nl.lp.mw.gg,https://your-other-hub.example \
  docker compose -f docker-compose.probe.yml up --build
```

By default the probe **detects its own location from its public IP** (free,
key-less geolocation with provider fallback), so it lands in the right spot on
the map with no configuration. To override it — or to pin a location when the
probe is behind a VPN — set `PROBE_LOCATION="Country,City,latitude,longitude"`.
Turn auto-detection off with `PROBE_GEOIP=false`. (A hub advertises its own
location the same way; override with `HUB_LOCATION` / `HUB_GEOIP`.) Location is
self-declared either way — there is no proof-of-location.

The hub assigns your probe a share of the network's checks rather than all of
them, and your probe never runs more than `MAX_CHECKS_PER_MINUTE` (default 300) —
so lending a small box doesn't mean drowning it. Set `DISABLE_CHECKS=icmp,traceroute`
if your host can't grant the `NET_RAW` capability those checks need.

> **`MAX_CHECKS_PER_MINUTE` is also a network-wide cost dial, not just a local
> one.** It caps how many signed results your probe injects per minute. Each
> measurement costs a little CPU/bandwidth on your box, and a little disk +
> bandwidth on the **hubs that store its shard** (a handful of replicas, not every
> hub — results are sharded; see *Hub disk usage*). Hubs keep growth bounded by
> tiering old data down to summaries, but a lower cap still makes you a lighter
> network citizen, and a higher one raises the load you ask of others. Pick it for
> what your box — and the network — can comfortably carry.

---

## What gets checked

| Check       | What it tells you                              | Needs extra setup |
|-------------|------------------------------------------------|-------------------|
| HTTP(S)     | Is the site up? How fast? Right content?       | no                |
| TCP         | Is a port reachable?                           | no                |
| DNS         | Does the name resolve to the right answer?     | no                |
| TLS         | Is the certificate valid / about to expire?    | no                |
| ICMP ping   | Latency and packet loss                        | `NET_RAW` capability |
| Traceroute  | The network path and where it breaks           | `NET_RAW` capability |

> All six checks are implemented. ICMP and traceroute need raw sockets — the
> probe auto-detects this and simply doesn't offer them where the `NET_RAW`
> capability isn't granted.

---

## Hub disk usage

By default a hub stores a **capacity-weighted slice** of the network's results
(its shards) and fetches the rest from peers on demand — so it shows the same
global picture without holding everything. On a solo hub or a small mesh that
slice *is* everything (there aren't enough hubs to spread across yet), so disk
scales with how many results the network produces — driven by the number of
distinct checks, the redundancy target, the check interval, and every probe's
`MAX_CHECKS_PER_MINUTE` (the ceiling on results each probe injects). As the mesh
grows, each hub's share shrinks.

To keep even a full slice bounded — modest enough for a hobbyist VPS — a hub
**tiers results by age, keeping less detail the further back you look**
(TimescaleDB):

| Age | What's kept | Default |
|-----|-------------|---------|
| Recent | every result, full detail (compressed) | 7 days |
| Older | hourly summaries (up/down counts, latency min/avg/max) | 90 days |
| Oldest | daily summaries | 730 days |
| Beyond | dropped | — |

That coarser history is **served**, not just stored: `GET
/api/v1/results/history?check_id=…&from_ms=…&to_ms=…` returns rolled-up summaries
(hourly for short ranges, daily for long ones), and the dashboard shows a
per-service uptime strip from it. These summaries are locally-derived aggregates,
**not** individually probe-signed records (unlike live results). On rollout the
aggregates are refreshed over existing history before retention can drop the raw
rows, so enabling tiering doesn't lose what's already stored.

The result is **bounded, flat disk** rather than unbounded growth: a small hub
following a few hundred checks settles around a few GB and stays there, while
still keeping two years of (coarser) history. Tune the windows with
`RESULT_RETENTION_DAYS`, `RESULT_HOURLY_RETENTION_DAYS`,
`RESULT_DAILY_RETENTION_DAYS`, and `RESULT_COMPRESS_AFTER_DAYS` (see
`.env.example`; `0` = keep that tier forever). Running without a database
(`DATABASE_URL` unset) keeps results in memory only — fine for trials, not
persisted.

**Don't want to store the whole network either?** You don't have to. Set a
**storage role** with `HUB_STORAGE`: `shards` (default) holds a
capacity-weighted slice of the results and fetches the rest from peers on
demand; `archive` holds everything (a full mirror); `none` stores only its own
probes' data. `HUB_STORAGE_CAPACITY` sets how big a slice — a beefy server takes
more, a NAS less. A solo hub or small mesh still holds everything automatically,
so this only kicks in once the network is large enough to share the load. Check
`GET /api/v1/p2p` to see shard coverage.

### How much disk does a full archive hub need?

`HUB_STORAGE=archive` keeps a complete mirror of the network's results, so its
disk is driven entirely by how many results the network produces. A useful
rule of thumb: after TimescaleDB compression a raw result costs **roughly
~100 bytes on disk** (including index overhead). It doesn't compress to nothing
because every result carries a 64-byte Ed25519 signature — high-entropy bytes
that don't shrink — which is the floor you're paying for verifiable data.

The raw tier dominates the total (hourly/daily summaries are a much smaller,
bounded tail), so estimate it directly:

```
results/day ≈ checks × redundancy × (86400 / interval_seconds)
raw disk    ≈ results/day × ~100 bytes × RESULT_RETENTION_DAYS
```

At the default 7-day raw window, 3× redundancy, and 60s intervals:

| Network size      | Results/day | Archive disk (raw tier, ~7d) |
|-------------------|-------------|------------------------------|
| 200 checks        | ~0.9M       | **< 1 GB**                   |
| 2,000 checks      | ~8.6M       | **~6 GB** (+ a few GB tail)  |
| 20,000 checks @5× @30s | ~290M  | **~200 GB**                  |

Those are rough, order-of-magnitude figures — the point is that a hobby-scale
mirror is a few GB and stays flat, while a full archive of a large network is a
deliberately heavy choice (which is exactly why `shards` is the default).

**Tuning the disk you're willing to spend** (all in `.env`, see `.env.example`):

- **Shorten the raw window** — `RESULT_RETENTION_DAYS` is the biggest lever;
  it scales the dominant tier linearly. Halve it, halve the bulk.
- **Compress sooner** — lower `RESULT_COMPRESS_AFTER_DAYS` so recent data spends
  less time uncompressed.
- **Trim the long tail** — `RESULT_HOURLY_RETENTION_DAYS` /
  `RESULT_DAILY_RETENTION_DAYS` bound the summary tiers (set `0` to keep a tier
  forever — unbounded growth, the opposite knob).
- **Or don't archive at all** — `HUB_STORAGE=shards` with a
  `HUB_STORAGE_CAPACITY` sized to your box holds only a slice and fetches the
  rest from peers, which is how most hubs should run. `archive` is for operators
  who specifically want a full mirror (a community backstop, analytics, etc.).

---

## Is it trustworthy? (the honest part)

LibrePing is decentralized, which raises a fair question: if anyone can join,
why believe the data?

- Every result is **signed** by the probe that produced it, and **every hub
  verifies that signature**. Forged or tampered results are dropped on arrival.
- The default policy is **open**: hubs accept any validly-signed result but
  always show **where it came from**, and trust comes from **corroboration** —
  multiple independent probes agreeing. Operators who want stricter guarantees
  can switch to an **allowlist** of trusted probes.
- **Your alert destinations stay private.** Alert rules are gossiped network-wide,
  but the destination is encrypted (X25519 sealed box) to only the few hubs that
  may notify you, so other hub operators see ciphertext, not your URL/topic.
- **Honest caveat:** a probe's *location* is self-declared. It's auto-detected
  from the node's public IP by default (and can be overridden), but IP
  geolocation is a convenience, not proof — there's no way to cryptographically
  prove geography. Treat locations as claims corroborated by the mesh, not as
  proof.
- **Honest caveat:** alert delivery is *at-least-once*, not exactly-once — that's
  impossible against external endpoints — so in the rare moment a hub fails over
  you might get a duplicate notification rather than none.

---

## For developers

LibrePing is Go (hub + probe) and React/TypeScript (dashboard). The hub and
probe share a `pkg/` module (`identity` for the Ed25519 signing/trust core,
`protocol` for the wire contract, `geoip` for IP-based location auto-detection,
`netguard` for SSRF defenses). The hub is split into focused packages: `p2p`
(libp2p gossip mesh), `assign` (check distribution), `shard`/`interest`/`remote`
(partial result replication), `directory` (peer-hub registry), `alert`
(evaluation + delivery), and `encbox` (sealed alert destinations). Quick version:

```bash
make build   # build all Go modules
make test    # run all tests, including the peer-to-peer gossip integration test
make web     # build the dashboard
```

## License

[AGPL-3.0](./LICENSE) — LibrePing is free software. If you run a modified
version as a network service, you must share your changes.
