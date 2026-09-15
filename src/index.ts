import { baseLog, logEntry } from "./lib/log";
import { handleOob, type OobEnv } from "./handlers/oob";
import {
  canaryText,
  injectText,
  injectSoftText,
  injectMarkdown,
  injectHtml,
  injectJson,
  injectRobots,
  toolPoison,
} from "./handlers/ai";
import {
  jsonPayload,
  yamlPayload,
  xmlPayload,
  htmlPayload,
  jsPayload,
  ssrfRedirect,
  ssrfIncludeYaml,
  ssrfChainedYaml,
  ssrfSweepYaml,
  xssPayload,
} from "./handlers/payloads";

/**
 * A generic testing collector: somewhere to point a payload, and somewhere to
 * watch for it arriving. Nothing here is tied to a particular target — the
 * per-target harnesses that used to live in this worker are on the
 * archive/old-targets branch.
 */
export default {
  async fetch(request: Request, env: OobEnv): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const log = baseLog(request);

    // ── OOB collector ──────────────────────────────────────────
    // First, because once a wildcard record exists a callback can arrive on
    // any host label and must not fall through to a payload route.
    {
      const res = await handleOob(request, env);
      if (res) return res;
    }

    // ── Prompt injection documents ─────────────────────────────
    if (path === "/ai/canary.txt") return canaryText(request);
    if (path === "/ai/inject.txt") return injectText(request);
    if (path === "/ai/inject-soft.txt") return injectSoftText(request);
    if (path === "/ai/inject.md") return injectMarkdown(request);
    if (path === "/ai/inject.html") return injectHtml(request);
    if (path === "/ai/inject.json") return injectJson(request);
    if (path === "/ai/robots-inject.txt") return injectRobots(request);
    if (path === "/ai/tool-poison.json") return toolPoison(request);

    // ── Payload routes ─────────────────────────────────────────
    if (path === "/json") return jsonPayload(request);
    if (path === "/yaml") return yamlPayload(request);
    if (path === "/xml") return xmlPayload(request);
    if (path === "/html") return htmlPayload(request);
    if (path === "/js") return jsPayload(request);

    // ── SSRF routes ────────────────────────────────────────────
    if (path === "/ssrf") return ssrfRedirect(request);
    if (path === "/ssrf/sweep.yml") return ssrfSweepYaml(request, url.origin);
    if (path === "/ssrf-include-remote.yml") return ssrfIncludeYaml(request, url.origin);
    if (path === "/ssrf-chained.yml") return ssrfChainedYaml(request, url.origin);

    // ── XSS routes ─────────────────────────────────────────────
    if (path === "/xss") return xssPayload(request);

    // ── Health check ───────────────────────────────────────────
    if (path === "/") {
      logEntry({ ...log, event: "health" });
      return new Response(
        JSON.stringify(
          {
            status: "ok",
            version: "3.0.0",
            service: "generic-testing-collector",
            endpoints: {
              oob: [
                "/oob/<token>                generic callback collector",
                "/oob/<token>.gif            answers a 1x1 GIF, for <img> callbacks",
                "/oob/<token>.js             answers JavaScript, for <script src> callbacks",
                "/oob?token=<token>          query form",
                "/oob/hits?token=<token>     what called back (needs the OOB KV binding)",
                "/oob/admin/hits?token=<token> token-scoped authenticated raw log access",
                "/oob/admin/tokens?limit=10 latest callback tokens (authenticated)",
                "/oob/admin/responses       create an authenticated response capability",
                "/r/<capability>            use a provisioned GET/HEAD response or redirect chain",
                "/redirect/<token>?to=<url>&status=302",
                "/redirect-chain/<token>?to=<url>&hops=3&status=302",
                "/respond/<token>?status=200&content_type=text/plain",
                "/delay/<token>?ms=1000",
                "/json/<token>?callback=<fn>",
                "/js/<token>?callback=<fn>",
                "<token>.<this host>         host form (needs a wildcard DNS record)",
              ],
              ai: [
                "/ai/canary.txt?token=<t>    benign retrieval control",
                "/ai/inject.txt?token=<t>     injection in plain text, the usual RAG chunk",
                "/ai/inject-soft.txt?token=   secondary fetch without a classic jailbreak phrase",
                "/ai/inject.md?token=<t>      injection hidden in an HTML comment",
                "/ai/inject.html?token=<t>    injection invisible on screen, present in the DOM",
                "/ai/inject.json?token=<t>    injection in a free-text record field",
                "/ai/robots-inject.txt?token= injection in robots.txt, for crawlers that feed it to a model",
                "/ai/tool-poison.json?token=  MCP tools/list whose tool description carries the injection",
              ],
              ssrf: [
                "/ssrf?url=<target>",
                "/ssrf/sweep.yml?hosts=127.0.0.1:80,169.254.169.254:80&token=<t>",
                "/ssrf-include-remote.yml?target=<callback_url>",
                "/ssrf-chained.yml",
              ],
              xss: ["/xss?payload=<script>alert(1)</script>"],
              payloads: [
                "/json?callback=<fn>",
                "/yaml",
                "/xml",
                "/html?title=<title>",
                "/js?callback=<fn>",
              ],
            },
            note:
              "The /ai injection payloads ask the model to fetch their /oob/<token> URL. A model " +
              "repeating a phrase proves it read the text; a request arriving at the " +
              "collector proves it acted, and only the second is worth reporting.",
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
