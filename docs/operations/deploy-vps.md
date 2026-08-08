# Deploy AgentShield to a VPS (testing server)

This runbook deploys AgentShield as a testing server on a VPS with Docker Compose, Caddy (auto-TLS),
and a bearer-token-protected API. The dashboard is served as static files behind the same TLS
endpoint.

> **Security review required before production.** This setup is for testing. Before exposing
> sensitive data, complete human security review of authentication, TLS, and network isolation per
> `PENDING.md` §9. The bearer token is a single shared secret; production needs scoped API tokens,
> RBAC, and tenant isolation.

## Prerequisites

- A VPS with **Docker Engine 24+** and **Docker Compose v2+**.
- A **domain name** with an **A record** pointing to the VPS public IP (Caddy needs this for
  automatic Let's Encrypt TLS).
- Ports **80** and **443** open on the VPS firewall.
- SSH access to the VPS.

## Architecture

```
Internet → Caddy (80/443, TLS) → dashboard static files at /
                              └→ reverse proxy /v1/* and /health → API (4141, internal only)
```

- **API container**: Node.js, internal network only, bearer-token auth + rate limiting, read-only
  filesystem, data on a named volume.
- **Caddy container**: TLS termination, serves the built dashboard SPA, reverse-proxies API calls.

## Steps

### 1. Clone the repository on the VPS

```bash
ssh user@your-vps
git clone https://github.com/agentshield/agentshield.git
cd agentshield
```

### 2. Generate an API token

```bash
node packages/cli/dist/cli.cjs --version   # verify Node 22+ is available
# Or use the API's built-in generator:
cd apps/api && npx tsx src/index.ts --generate-token
# Copy the output, e.g. as_abc123def456...
```

If Node is not on the VPS yet, generate the token locally and copy it over.

### 3. Configure environment

```bash
cd deploy/compose
cp .env.example .env
nano .env
```

Set:
```env
AGENTSHIELD_DOMAIN=agentshield.yourdomain.com
AGENTSHIELD_API_TOKEN=as_<the-token-you-generated>
AGENTSHIELD_ALLOWED_ORIGINS=https://agentshield.yourdomain.com
```

### 4. Build and start

```bash
docker compose -f docker-compose.vps.yml up -d --build
```

The first build takes a few minutes (pnpm install + esbuild + Vite). Caddy automatically obtains
TLS certificates from Let's Encrypt on the first request.

### 5. Verify

```bash
# Health (public, no token needed)
curl https://agentshield.yourdomain.com/health
# Expect: {"status":"ok","authEnabled":true,...}

# Authenticated API call
curl -H "Authorization: Bearer as_<your-token>" \
     https://agentshield.yourdomain.com/v1/rules?kind=memory

# Unauthorized call should return 401
curl https://agentshield.yourdomain.com/v1/scans
# Expect: {"error":{"code":"unauthorized",...}}

# Dashboard should load in a browser at https://agentshield.yourdomain.com
```

### 6. Check logs

```bash
docker compose -f docker-compose.vps.yml logs -f api
docker compose -f docker-compose.vps.yml logs -f caddy
```

## Maintenance

### Update to a new version

```bash
cd agentshield
git pull --ff-only
cd deploy/compose
docker compose -f docker-compose.vps.yml up -d --build
```

Data in the `agentshield-data` volume persists across rebuilds. The memory assessment cache is keyed
by detector version, so a detector upgrade safely invalidates only affected records.

### Backup

```bash
# Back up the data volume (scans, memory audits, quarantine, remediation, events, consent)
docker run --rm -v agentshield_agentshield-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/agentshield-data-$(date +%Y%m%d).tar.gz /data
```

### Rotate the API token

1. Generate a new token: `npx tsx apps/api/src/index.ts --generate-token`
2. Update `deploy/compose/.env` with the new `AGENTSHIELD_API_TOKEN`.
3. Restart: `docker compose -f docker-compose.vps.yml restart api`
4. Update any clients with the new bearer token.

### Stop / tear down

```bash
docker compose -f docker-compose.vps.yml down
# To remove data volumes as well (destructive):
docker compose -f docker-compose.vps.yml down -v
```

## Resource notes for 4C/8G/80G

- The API + Caddy stack uses ~200–400 MB RAM at idle.
- Disk: Docker images ~500 MB, data volume grows with scans/audits (plan 1–10 GB for testing).
- Rate limit default: 200 requests / 60s. Tune via `AGENTSHIELD_RATE_LIMIT_MAX` in `.env`.

## Without a domain (IP-only testing)

If you do not have a domain, Caddy cannot obtain Let's Encrypt certificates. Use self-signed TLS
or plain HTTP for local testing only:

```bash
# In .env, set:
AGENTSHIELD_DOMAIN=:80
# And use the local docker-compose.yml instead (bound to 127.0.0.1):
docker compose up -d --build
# Then tunnel: ssh -L 4141:127.0.0.1:4141 user@your-vps
```

## Security checklist before wider exposure

- [ ] TLS active (verify with `curl -v https://...`)
- [ ] API token set and non-empty
- [ ] CORS origins restricted to your domain
- [ ] Rate limiting active (check `/health` response)
- [ ] API container has no ports published to the host (only Caddy is exposed)
- [ ] Firewall allows only 80/443 inbound
- [ ] Data volume backed up
- [ ] Token rotated if shared over insecure channels
