# hooks — generic testing collector

A Cloudflare Worker that gives a payload somewhere to point and a place to
watch for it arriving. Nothing here is tied to a particular target; the
per-target harnesses that used to live here are on the `archive/old-targets`
branch.

Use it only against systems you are authorised to test.

## Out-of-band collector

A tool plants a unique token and watches here for it. The request that lands is
the evidence, so everything about it is recorded: method, URL, IP, ASN,
country, colo, the interesting headers, query parameters and a body preview.
`Authorization` and `Cookie` are kept deliberately — when a target sends those
to a third-party collector, that is the finding.

| Form | Use |
|---|---|
| `/oob/<token>` | Works with the DNS that exists today |
| `/oob/<token>.gif` | Answers a 1x1 GIF, so a callback can ride in an `<img>` |
| `/oob/<token>.js` | Answers JavaScript, for `<script src>` |
| `/oob?token=<token>` | For payloads that cannot carry a path |
| `/oob/admin/hits?token=<token>` | Authenticated raw hits endpoint |
| `/oob/admin/tokens?limit=10` | Authenticated list of recently active callback tokens |
| `/oob/admin/responses` | Authenticated creation of an expiring response capability |
| `/r/<start-token>` | Public, unguessable provisioned GET/HEAD response or redirect chain |
| `<token>.hooks.…` | Fires on DNS resolution alone — needs a wildcard record |
| `/oob/hits?token=<token>` | What called back |
| `/json/<token>?callback=<fn>` | Controlled JSON response route |
| `/js/<token>?callback=<fn>` | Controlled JS/JSONP response |
| `/respond/<token>` | Controlled status/content/cookies/headers route |
| `/delay/<token>` | Bounded delay response route |
| `/redirect/<token>?to=<url>` | Controlled redirect route |
| `/redirect-chain/<token>?to=<url>&hops=3` | Controlled redirect chain start |

The host form is worth enabling: it fires when the target can resolve a name
even if it cannot make an outbound HTTP request, which catches cases the path
form misses. It needs a wildcard DNS record and a matching worker route.

Responses are always JSON, a GIF, or a JS comment — never the caller's own
content reflected back. A collector that echoed input as HTML would be an XSS
gadget aimed at whoever reads the results.

### Storage

Without a KV binding, hits go to observability logs only and `/oob/hits`
returns `501` rather than an empty list. An empty list would read as "nothing
called back", which is the one answer it must never give when it cannot know.

To make hits queryable — which is what lets a scanner confirm a callback
without a human opening the dashboard:

```bash
npx wrangler kv namespace create OOB
# add the returned id to wrangler.toml as a kv_namespaces binding named OOB
```

## Prompt injection documents

Direct injection is mostly a curiosity. The payable version is indirect:
content a model ingests without a human reading it first. The instruction has
to survive whatever pipeline carries it, so the same payload is offered in the
formats those pipelines accept.

| Endpoint | Where the instruction hides |
|---|---|
| `/ai/canary.txt?token=<t>` | Benign retrieval control with no instruction |
| `/ai/inject.txt?token=<t>` | Plain text, the usual RAG chunk |
| `/ai/inject-soft.txt?token=<t>` | Plain text with a softer verification request |
| `/ai/inject.md?token=<t>` | An HTML comment — invisible in rendered markdown |
| `/ai/inject.html?token=<t>` | Off-screen and zero-size elements: in the DOM, not on screen |
| `/ai/inject.json?token=<t>` | A free-text record field, where user content lives |
| `/ai/robots-inject.txt?token=<t>` | `robots.txt`, for crawlers that feed it to a model as guidance |
| `/ai/tool-poison.json?token=<t>` | An MCP `tools/list` whose tool *description* carries the instruction |

Every payload asks the model to fetch its own `/oob/<token>` URL. That is the
point: a model repeating a phrase proves it read the text, while a request
arriving at the collector proves it acted, and only the second is worth
reporting.

Use `/ai/canary.txt` first. If the assistant cannot repeat its token, the
document was not retrieved and a failed injection probe says nothing about
instruction handling. Compare `/ai/inject-soft.txt` with `/ai/inject.txt` to
separate phrase-based filtering from the absence of an outbound tool.

`tool-poison.json` is the supply-chain form. An agent that trusts a third-party
MCP server reads tool descriptions into its own context, so a description is
executable text in practice — and the poisoning usually arrives as a
description change on a server that was previously benign.

None of these instructions asks for a write, a purchase, or a message to a
third party. Keep it that way.

## SSRF

| Endpoint | Use |
|---|---|
| `/ssrf?url=<target>` | Plain 302 |
| `/ssrf/sweep.yml?hosts=a:80,b:443&token=<t>` | A document referencing each host, for SSRF that runs through a parser. Hosts come from the caller, capped at 25 |
| `/ssrf-include-remote.yml?target=<url>` | Remote-include chain |
| `/ssrf-chained.yml` | Multi-stage CI-shaped chain |

Each sweep entry also calls the collector, so a fetch that succeeds is visible
even when the response never reaches you.

## XSS and content-type payloads

`/xss?payload=…`, `/json?callback=…`, `/yaml`, `/xml`, `/html?title=…`,
`/js?callback=…`.

These reflect what you pass them, by design — they exist to be loaded by a
target, not to be visited by anyone else.

## Development

```bash
npx wrangler dev --local     # http://127.0.0.1:8787
npx tsc --noEmit             # typecheck
npx wrangler deploy          # ship it
```

## Deployment notes

Keep secrets in Cloudflare bindings, not source control:

```bash
wrangler secret put ADMIN_TOKEN
```

`OOB` must be a KV namespace binding to enable persistent hit storage and token-scoped deletion.
Set non-secret limits as Worker variables in Cloudflare or in `wrangler.toml`.
New callback records store selected Cloudflare request metadata—network,
location, HTTP/TLS versions, Ray/request identity—and redacted request headers
so local evidence viewers do not need access to Cloudflare logs.

## Route classes and classification

- `callback_hit`: tokenized callback endpoints like `/oob/<token>`, `/json/<token>`, `/js/<token>`.
- `hits_query`: `/oob/hits` polling.
- `admin_request`: controlled response, redirect, and authenticated raw-log routes.

## Security and privacy behaviour

- Sensitive headers are redacted by default: `Authorization`, `Cookie`,
  `Set-Cookie`, any header containing `token`, `secret`, `key`, `session`, and
  proxy auth headers.
- Values are preserved for `X-Research-Marker` and `X-Codex-Probe`.
- Public `/oob/hits` responses only expose redacted metadata and omit sensitive
  values.
- Redirect targets are limited to `http` and `https`; unsafe schemes like
  `javascript:`, `data:`, and `file:` are blocked.
- Header injection is blocked in response/header query parameters.
- CORS is intentionally not enabled.
- No server-side URL fetching is performed.
- No open proxy behavior in callback endpoints.

## Environment bindings and tuning

- `ADMIN_TOKEN`: required for `/oob/admin/hits`, `/respond`, `/delay`, `/redirect`, `/redirect-chain`.
- Response capabilities are created through authenticated `POST /oob/admin/responses`, expire after 24 hours, and never contain the admin token. The public `/r/<start-token>` route accepts only GET and HEAD.
- `HIT_TTL_SECONDS`: retention window (default: `604800`).
- `MAX_HITS_PER_TOKEN`: per-token hit cap (default: `50`).
- `MAX_BODY_BYTES`: max captured body size.
- `MAX_BODY_PREVIEW_BYTES`: public body preview cap.
- `MAX_REDIRECT_HOPS`: redirect hop cap.
- `MAX_RESPONSE_BYTES`: response body cap for controlled routes.
- `MAX_RESPONSE_HEADERS`: max custom response headers accepted as `header-*`.
- `MAX_REQUESTS_PER_MINUTE`: per-IP request limit.
- `MAX_DELAY_MS`: response delay cap for `/respond` and `/delay`.
- `TOKEN_MIN_LENGTH`: token length lower bound.
- `TOKEN_MAX_LENGTH`: token length upper bound.
- `ADMIN_TOKEN_HEADER`: optional custom admin auth header name.

## Example usage

```bash
TOKEN=aaaaaaaaaaaaaaaaaaaaaaaa
curl "https://hooks.mement0rq.com/oob/$TOKEN"         # collect callback
curl "https://hooks.mement0rq.com/oob/hits?token=$TOKEN"
curl -H "Authorization: Bearer <ADMIN_TOKEN>" \
  "https://hooks.mement0rq.com/oob/admin/hits?token=$TOKEN"

curl "https://hooks.mement0rq.com/respond/$TOKEN?status=200&content_type=text/plain&body=ok"
curl "https://hooks.mement0rq.com/delay/$TOKEN?ms=1000&status=204"
curl "https://hooks.mement0rq.com/redirect/$TOKEN?to=https%3A%2F%2Fexample.com%2Fcb&status=302"
curl "https://hooks.mement0rq.com/redirect-chain/$TOKEN?to=https%3A%2F%2Fexample.com%2Fcb&hops=3&status=302"
curl "https://hooks.mement0rq.com/json/$TOKEN?callback=probe"
curl "https://hooks.mement0rq.com/js/$TOKEN?callback=probe&status=200"

# Android WebView callback check
curl "https://hooks.mement0rq.com/oob/$TOKEN?q=android-webview&state=webview"

# OAuth callback check
curl "https://hooks.mement0rq.com/oob/$TOKEN?response_type=code&state=oauth"
```

Delete token-scoped records with an authenticated admin request:

```bash
curl -X DELETE -H "Authorization: Bearer <ADMIN_TOKEN>" \
  "https://hooks.mement0rq.com/oob/admin/hits?token=$TOKEN&hit_id=<hit-id>"
```

Filter by time and event type:

```bash
curl "https://hooks.mement0rq.com/oob/hits?token=$TOKEN&event_type=callback_hit&since=2026-09-01T00:00:00Z&until=2026-09-10T23:59:59Z"
```
