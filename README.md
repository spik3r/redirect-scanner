# Generic Webhook API

Cloudflare Worker providing a generic webhook API with payload generation
for security testing (SSRF, XSS) and general webhook consumption.

Originally built for GitLab SSRF scanning via `include:remote:` CI pipelines.

## Endpoints

### Health

| Path | Description |
|------|-------------|
| `/`  | API index with all available endpoints |

### GitLab SSRF Scanner

| Path | Description |
|------|-------------|
| `/gitlab/scan.yml` | 302 redirect to next internal target (cycles) |
| `/gitlab/status`   | Current scan position |
| `/gitlab/reset`    | Reset scanner to target #1 |
| `/gitlab/targets`  | List all scan targets |

### SSRF

| Path | Description |
|------|-------------|
| `/ssrf?url=<target>` | 302 redirect to any URL |
| `/ssrf-include-remote.yml?target=<callback>` | GitLab `include:remote:` YAML payload |

### XSS

| Path | Description |
|------|-------------|
| `/xss?payload=<script>alert(1)</script>` | Reflected XSS payload (HTML page) |

### Generic Payloads

| Path | Description |
|------|-------------|
| `/json?callback=<fn>` | JSON response (JSONP if callback provided) |
| `/yaml` | YAML response |
| `/xml` | XML response |
| `/html?title=<title>` | HTML page |
| `/js?callback=<fn>` | JavaScript payload |

## Deploy

```bash
npm install
npx wrangler login
npm run deploy
```

## Local Dev

```bash
npm run dev          # wrangler dev (local server)
npm run typecheck    # TypeScript type checking
npm run logs         # tail production logs
```

## GitLab SSRF Workflow

1. Deploy this worker
2. Point `.gitlab-ci.yml` at `https://your-worker.workers.dev/gitlab/scan.yml`
   or use the remote include: `include: remote: "https://your-worker.workers.dev/ssrf-include-remote.yml"`
3. Each pipeline triggers fetch → 302 redirect to next internal target
4. Monitor pipeline errors to detect live services

### Signal Interpretation

| Pipeline Error | Meaning |
|----------------|---------|
| `Invalid configuration format` | **SERVICE FOUND** — port open, responded (non-YAML) |
| `timeout error` after 3 attempts | Firewall drop or dead IP |
| `connection refused` | IP alive, port closed |
| `blocked/not allowed` | UrlBlocker blocked the IP |
