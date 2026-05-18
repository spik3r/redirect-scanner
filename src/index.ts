import { baseLog, logEntry } from "./lib/log";
import { TARGETS } from "./lib/targets";
import { handleGitlab } from "./handlers/gitlab";
import {
  jsonPayload,
  yamlPayload,
  xmlPayload,
  htmlPayload,
  jsPayload,
  ssrfRedirect,
  ssrfIncludeYaml,
  ssrfChainedYaml,
  xssPayload,
} from "./handlers/payloads";

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const log = baseLog(request);

    // ── GitLab routes ──────────────────────────────────────────
    if (path.startsWith("/gitlab")) {
      const res = handleGitlab(request);
      if (res) return res;
    }

    // ── Payload routes ─────────────────────────────────────────
    if (path === "/json") return jsonPayload(request);
    if (path === "/yaml") return yamlPayload(request);
    if (path === "/xml") return xmlPayload(request);
    if (path === "/html") return htmlPayload(request);
    if (path === "/js") return jsPayload(request);

    // ── SSRF routes ────────────────────────────────────────────
    if (path === "/ssrf") return ssrfRedirect(request);
    if (path === "/ssrf-include-remote.yml") return ssrfIncludeYaml(request, url.origin);
    if (path === "/ssrf-chained.yml") return ssrfChainedYaml(request, url.origin);

    // ── XSS routes ─────────────────────────────────────────────
    if (path === "/xss") return xssPayload(request);

    // ── Health check ───────────────────────────────────────────
    if (path === "/") {
      logEntry({ ...log, event: "health", total_targets: TARGETS.length });
      return new Response(
        JSON.stringify(
          {
            status: "ok",
            version: "2.0.0",
            service: "generic-webhook-api",
            endpoints: {
              gitlab: ["/gitlab/scan.yml", "/gitlab/status", "/gitlab/reset", "/gitlab/targets"],
              ssrf: ["/ssrf?url=<target>", "/ssrf-include-remote.yml?target=<callback_url>", "/ssrf-chained.yml"],
              xss: ["/xss?payload=<script>alert(1)</script>"],
              payloads: ["/json?callback=<fn>", "/yaml", "/xml", "/html?title=<title>", "/js?callback=<fn>"],
            },
            targets: TARGETS.length,
          },
          null,
          2
        ),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // ── 404 ────────────────────────────────────────────────────
    logEntry({ ...log, event: "404", path });
    return new Response(
      JSON.stringify({ error: "Not Found", path, hint: "Visit / for available endpoints" }),
      { status: 404, headers: { "Content-Type": "application/json" } }
    );
  },
};
