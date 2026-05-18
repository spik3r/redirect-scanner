# Redirect Scanner — GitLab SSRF Internal Port Scanner

Cloudflare Worker that cycles 302 redirects through internal IP ranges
to map accessible services via GitLab's `include: remote:`.

## How It Works

1. Deploy this worker to Cloudflare
2. Point `.gitlab-ci.yml` at `https://your-worker.workers.dev/scan.yml`
3. Each push creates a pipeline → GitLab fetches `/scan.yml` → gets 302 to next target
4. Monitor pipeline timing/errors to detect live services
5. Push again for next target (or use GET /scan.yml directly to cycle)

## Signal Interpretation

| Pipeline Error | Meaning |
|---------------|---------|
| `Invalid configuration format` | **SERVICE FOUND** — port open, responded (non-YAML) |
| `timeout error` after 3 attempts | Firewall drop or dead IP |
| `connection refused` | IP alive, port closed |
| `blocked/not allowed` | UrlBlocker blocked the IP |

## Deploy

```bash
npm install
npx wrangler login
npm run deploy
```

## Endpoints

| Path | Purpose |
|------|---------|
| `/scan.yml` | 302 redirect to next target (cycles automatically) |
| `/status` | Show current scan position |
| `/reset` | Reset scanner to target #1 |
| `/targets` | List all scan targets |

## Logs

```bash
npm run logs          # live tail
# Or view in Cloudflare Dashboard → Workers → Logs
```
