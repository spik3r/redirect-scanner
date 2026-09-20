export interface FixtureDefinition {
  path: string;
  description: string;
}

const GIF = decodeBase64("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==");
const PNG = decodeBase64("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=");
const INVALID_GIF = new TextEncoder().encode("NOT_A_GIF_MEMENT0RQ_20260915");
const HTML_AS_IMAGE = new TextEncoder().encode("<!doctype html><title>Fixture</title><p>MEMENT0RQ_HTML_AS_IMAGE_20260915</p>");
const SVG = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg" width="160" height="40" viewBox="0 0 160 40"><rect width="160" height="40" fill="#23283d"/><text x="8" y="25" fill="#9ece6a">Mement0rq fixture</text></svg>');

const FIXTURES = new Map<string, { body: Uint8Array; type: string; id: string; description: string; extra?: Record<string, string> }>([
  ["/fixtures/valid-gif-correct-mime.gif", { body: GIF, type: "image/gif", id: "valid-gif-correct-mime", description: "Valid 1×1 GIF with the correct image/gif MIME type." }],
  ["/fixtures/valid-gif-no-extension", { body: GIF, type: "image/gif", id: "valid-gif-no-extension", description: "Valid 1×1 GIF with no filename extension." }],
  ["/fixtures/valid-gif-octet-stream.gif", { body: GIF, type: "application/octet-stream", id: "valid-gif-octet-stream", description: "Valid 1×1 GIF served as application/octet-stream." }],
  ["/fixtures/valid-gif-text-plain.gif", { body: GIF, type: "text/plain", id: "valid-gif-text-plain", description: "Valid 1×1 GIF served as text/plain." }],
  ["/fixtures/invalid-gif-image-mime.gif", { body: INVALID_GIF, type: "image/gif", id: "invalid-gif-image-mime", description: "Invalid GIF marker bytes served as image/gif." }],
  ["/fixtures/valid-gif-wrong-extension.txt", { body: GIF, type: "image/gif", id: "valid-gif-wrong-extension", description: "Valid 1×1 GIF with a .txt extension." }],
  ["/fixtures/valid-png-correct-mime.png", { body: PNG, type: "image/png", id: "valid-png-correct-mime", description: "Valid 1×1 PNG with the correct image/png MIME type." }],
  ["/fixtures/svg-image.svg", { body: SVG, type: "image/svg+xml", id: "svg-image", description: "Static SVG rectangle and text with no active content." }],
  ["/fixtures/html-as-image.gif", { body: HTML_AS_IMAGE, type: "image/gif", id: "html-as-image", description: "Harmless HTML marker served as image/gif." }],
  ["/fixtures/oversized-declared-gif.gif", { body: GIF, type: "image/gif", id: "oversized-control", description: "Small valid GIF control; Content-Length is not falsified.", extra: { "X-Mement0rq-Fixture": "oversized-control" } }],
]);

const REDIRECT_TARGETS: Record<string, string> = {
  "valid-gif": "/fixtures/valid-gif-correct-mime.gif",
  "gif-octet-stream": "/fixtures/valid-gif-octet-stream.gif",
  "invalid-gif": "/fixtures/invalid-gif-image-mime.gif",
};
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const SPECIAL_REDIRECT_TARGETS: Record<string, string> = {
  "valid-gif-final-no-extension": "/fixtures/valid-gif-no-extension",
  "cross-host-valid-gif": "https://fixtures-alt.mement0rq.com/fixtures/valid-gif-correct-mime.gif",
};
const OEMBED_CASES = ["safe", "special-title", "html-canaries", "malformed", "wrong-mime"] as const;
const OEMBED_ORIGIN = "https://hooks.mement0rq.com";
const OEMBED_ALT_ORIGIN = "https://fixtures-alt.mement0rq.com";

type OembedCase = typeof OEMBED_CASES[number];

export const fixtureDefinitions: FixtureDefinition[] = [
  ...[...FIXTURES.entries()].map(([path, fixture]) => ({ path, description: fixture.description })),
  ...[301, 302, 303, 307, 308].flatMap((status) => Object.entries(REDIRECT_TARGETS).flatMap(([name, target]) => [
    { path: `/fixtures/redirect/${status}/${name}`, description: `${status} same-origin redirect to ${target}.` },
    { path: `/fixtures/redirect/${status}/${name}.gif`, description: `${status} same-origin redirect alias ending in .gif to ${target}.` },
  ])),
  ...[301, 302, 303, 307, 308].flatMap((status) => Object.entries(SPECIAL_REDIRECT_TARGETS).map(([name, target]) => ({
    path: `/fixtures/redirect/${status}/${name}.gif`,
    description: `${status} fixed redirect to ${target}.`,
  }))),
  ...OEMBED_CASES.flatMap((name) => [
    { path: `/fixtures/oembed/page/${name}`, description: `oEmbed discovery page for the fixed ${name} case.` },
    { path: `/fixtures/oembed/json/${name}`, description: `Fixed ${name} oEmbed response.` },
  ]),
  ...[301, 302, 303, 307, 308].flatMap((status) => OEMBED_CASES.flatMap((name) => [
    { path: `/fixtures/oembed/redirect/${status}/page/${name}`, description: `${status} same-host redirect to the ${name} discovery page.` },
    { path: `/fixtures/oembed/redirect/${status}/json/${name}`, description: `${status} same-host redirect to the ${name} JSON response.` },
    { path: `/fixtures/oembed/redirect/${status}/cross-host/page/${name}`, description: `${status} cross-host redirect to the ${name} discovery page.` },
    { path: `/fixtures/oembed/redirect/${status}/cross-host/json/${name}`, description: `${status} cross-host redirect to the ${name} JSON response.` },
  ])),
];

export function handleFixture(request: Request): Response | null {
  const url = new URL(request.url);
  if (url.pathname === "/fixtures") return fixtureOverview(request, url.origin);
  if (!url.pathname.startsWith("/fixtures/")) return null;
  if (request.method !== "GET" && request.method !== "HEAD") return fixtureResponse(request, null, 405, "method-not-allowed", { Allow: "GET, HEAD" });

  const fixture = FIXTURES.get(url.pathname);
  if (fixture) return fixtureResponse(request, fixture.body, 200, fixture.id, { "Content-Type": fixture.type, ...fixture.extra });

  const oembedPage = url.pathname.match(/^\/fixtures\/oembed\/page\/(safe|special-title|html-canaries|malformed|wrong-mime)$/);
  if (oembedPage) return oembedPageResponse(request, oembedPage[1] as OembedCase);
  const oembedJSON = url.pathname.match(/^\/fixtures\/oembed\/json\/(safe|special-title|html-canaries|malformed|wrong-mime)$/);
  if (oembedJSON) return oembedJSONResponse(request, oembedJSON[1] as OembedCase);
  const oembedRedirect = url.pathname.match(/^\/fixtures\/oembed\/redirect\/(301|302|303|307|308)\/(cross-host\/)?(page|json)\/(safe|special-title|html-canaries|malformed|wrong-mime)$/);
  if (oembedRedirect) {
    const status = Number(oembedRedirect[1]);
    const origin = oembedRedirect[2] ? OEMBED_ALT_ORIGIN : "";
    const destination = `${origin}/fixtures/oembed/${oembedRedirect[3]}/${oembedRedirect[4]}`;
    return fixtureResponse(request, null, status, `oembed-redirect-${status}-${oembedRedirect[2] ? "cross-host-" : ""}${oembedRedirect[3]}-${oembedRedirect[4]}`, { Location: destination });
  }

  const match = url.pathname.match(/^\/fixtures\/redirect\/(301|302|303|307|308)\/(valid-gif|gif-octet-stream|invalid-gif)(?:\.gif)?$/);
  const specialMatch = url.pathname.match(/^\/fixtures\/redirect\/(301|302|303|307|308)\/(valid-gif-final-no-extension|cross-host-valid-gif)\.gif$/);
  if (!match && !specialMatch) return fixtureResponse(request, null, 404, "not-found", { "Content-Type": "text/plain; charset=utf-8" });
  const selected = match || specialMatch!;
  const status = Number(selected[1]);
  if (!REDIRECT_STATUSES.has(status)) return fixtureResponse(request, null, 404, "not-found", { "Content-Type": "text/plain; charset=utf-8" });
  const target = match ? REDIRECT_TARGETS[match[2]] : SPECIAL_REDIRECT_TARGETS[selected[2]];
  return fixtureResponse(request, null, status, `redirect-${status}-${selected[2]}`, { Location: target });
}

function oembedPageResponse(request: Request, name: OembedCase): Response {
  const href = `${OEMBED_ORIGIN}/fixtures/oembed/json/${name}`;
  const body = new TextEncoder().encode(`<!doctype html><html><head><meta charset="utf-8"><title>Mement0rq oEmbed ${name}</title><link rel="alternate" type="application/json+oembed" href="${href}"></head><body><p>Fixed oEmbed discovery fixture: ${name}</p></body></html>`);
  return fixtureResponse(request, body, 200, `oembed-page-${name}`, { "Content-Type": "text/html; charset=utf-8" });
}

function oembedJSONResponse(request: Request, name: OembedCase): Response {
  if (name === "malformed") return fixtureResponse(request, new TextEncoder().encode('{"version":"1.0","type":"rich","title":'), 200, "oembed-json-malformed", { "Content-Type": "application/json; charset=utf-8" });
  const title = name === "special-title" ? 'Mement0rq "quotes" <angles> & ampersand — 雪 🌱' : `Mement0rq oEmbed ${name}`;
  const html = name === "html-canaries"
    ? '<div class="mement0rq-oembed-canary"><template><span data-event-canary="onerror=alert(1)" data-script-canary="script-shaped">&lt;script&gt;MEMENT0RQ_SCRIPT_CANARY_20260915&lt;/script&gt;</span></template><p>MEMENT0RQ_HTML_CANARY_20260915</p></div>'
    : '<div class="mement0rq-oembed">Harmless controlled oEmbed fixture</div>';
  const body = JSON.stringify({ version: "1.0", type: "rich", title, provider_name: "Mement0rq Fixtures", provider_url: OEMBED_ORIGIN, width: 640, height: 360, html });
  return fixtureResponse(request, new TextEncoder().encode(body), 200, `oembed-json-${name}`, { "Content-Type": name === "wrong-mime" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8" });
}

function fixtureResponse(request: Request, body: Uint8Array | null, status: number, id: string, extra: Record<string, string>): Response {
  const headers = new Headers({
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Mement0rq-Fixture": id,
    ...extra,
  });
  return new Response(request.method === "HEAD" ? null : body, { status, headers });
}

function fixtureOverview(request: Request, origin: string): Response {
  if (request.method !== "GET" && request.method !== "HEAD") return fixtureResponse(request, null, 405, "overview-method-not-allowed", { Allow: "GET, HEAD" });
  const rows = fixtureDefinitions.map((fixture) => `<tr><td><code>${escapeHTML(origin + fixture.path)}</code></td><td>${escapeHTML(fixture.description)}</td><td><button data-url="${escapeHTML(origin + fixture.path)}">Copy</button></td></tr>`).join("");
  const html = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Mement0rq public fixtures</title><style>body{font:15px ui-monospace,monospace;max-width:1200px;margin:2rem auto;padding:0 1rem;background:#1a1b26;color:#c0caf5}h1{color:#9ece6a}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:.65rem;border-bottom:1px solid #3b4261}code{color:#7dcfff;overflow-wrap:anywhere}button{background:#292e42;color:#c0caf5;border:1px solid #565f89;padding:.4rem .7rem}</style><h1>Harmless public test fixtures</h1><p>Fixed resources for testing software against endpoints controlled by the operator. These routes do not store requests.</p><table><thead><tr><th>URL</th><th>Description</th><th></th></tr></thead><tbody>${rows}</tbody></table><script>document.querySelectorAll('button').forEach(b=>b.onclick=()=>navigator.clipboard.writeText(b.dataset.url));</script>`;
  return fixtureResponse(request, new TextEncoder().encode(html), 200, "overview", { "Content-Type": "text/html; charset=utf-8" });
}

function decodeBase64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function escapeHTML(value: string): string {
  return value.replace(/[&<>"']/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character] || character);
}
