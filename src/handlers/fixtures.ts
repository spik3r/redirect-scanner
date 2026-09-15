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
];

export function handleFixture(request: Request): Response | null {
  const url = new URL(request.url);
  if (url.pathname === "/fixtures") return fixtureOverview(request, url.origin);
  if (!url.pathname.startsWith("/fixtures/")) return null;
  if (request.method !== "GET" && request.method !== "HEAD") return fixtureResponse(request, null, 405, "method-not-allowed", { Allow: "GET, HEAD" });

  const fixture = FIXTURES.get(url.pathname);
  if (fixture) return fixtureResponse(request, fixture.body, 200, fixture.id, { "Content-Type": fixture.type, ...fixture.extra });

  const match = url.pathname.match(/^\/fixtures\/redirect\/(301|302|303|307|308)\/(valid-gif|gif-octet-stream|invalid-gif)(?:\.gif)?$/);
  const specialMatch = url.pathname.match(/^\/fixtures\/redirect\/(301|302|303|307|308)\/(valid-gif-final-no-extension|cross-host-valid-gif)\.gif$/);
  if (!match && !specialMatch) return fixtureResponse(request, null, 404, "not-found", { "Content-Type": "text/plain; charset=utf-8" });
  const selected = match || specialMatch!;
  const status = Number(selected[1]);
  if (!REDIRECT_STATUSES.has(status)) return fixtureResponse(request, null, 404, "not-found", { "Content-Type": "text/plain; charset=utf-8" });
  const target = match ? REDIRECT_TARGETS[match[2]] : SPECIAL_REDIRECT_TARGETS[selected[2]];
  return fixtureResponse(request, null, status, `redirect-${status}-${selected[2]}`, { Location: target });
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
