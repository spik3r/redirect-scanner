import { baseLog, logEntry } from "../lib/log";

const ENCODER = new TextEncoder();
const PIXEL_GIF = Uint8Array.from([
  0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
  0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
]);

const CRLF_RE = /[\r\n]/;
const SAFE_JSONP_CALLBACK = /^[A-Za-z_$][A-Za-z0-9_$]*$/;
const REDACT_VALUE = "[REDACTED]";
const BODY_SHA_PREFIX = "sha256:";
const EVENT_TOKEN_RE = /^[A-Za-z0-9_-]+$/;
const ROUTE_PREFIXES = new Set(["oob", "monstera"]);

const SAFE_RESPONSE_HEADERS = new Set([
  "cache-control",
  "content-language",
  "content-type",
  "etag",
  "last-modified",
  "referrer-policy",
  "vary",
  "x-content-type-options",
]);

const SAFE_RESPONSE_STATUS = new Set([301, 302, 303, 307, 308]);

const SAFE_RESPONSE_CONTENT_TYPES = new Set([
  "text/plain",
  "text/plain; charset=utf-8",
  "application/json",
  "application/json; charset=utf-8",
  "application/xml",
  "text/xml",
  "text/html",
  "text/html; charset=utf-8",
  "application/javascript",
  "application/javascript; charset=utf-8",
  "text/javascript",
  "text/javascript; charset=utf-8",
  "image/svg+xml",
]);

const HEADER_VALUE_ALLOWLIST = new Set(["x-research-marker", "x-codex-probe"]);
const ALLOWED_REDIRECT_SCHEMES = /^https?:$/;

const DEFAULTS = {
  hitTtlSeconds: 60 * 60 * 24 * 7,
  maxHitsPerToken: 50,
  maxBodyBytes: 8 * 1024,
  maxBodyPreviewBytes: 2048,
  maxRedirectHops: 8,
  maxDelayMs: 5000,
  maxResponseBytes: 16 * 1024,
  maxResponseHeaders: 8,
  maxRequestsPerMinute: 120,
  minTokenLength: 24,
  maxTokenLength: 128,
};

const RATE_WINDOW_SECONDS = 60;

export interface OobEnv {
  OOB?: KVNamespace;
  ADMIN_TOKEN?: string;
  ADMIN_TOKEN_HEADER?: string;
  HIT_TTL_SECONDS?: string;
  MAX_HITS_PER_TOKEN?: string;
  MAX_BODY_BYTES?: string;
  MAX_BODY_PREVIEW_BYTES?: string;
  MAX_REDIRECT_HOPS?: string;
  MAX_DELAY_MS?: string;
  MAX_RESPONSE_BYTES?: string;
  MAX_RESPONSE_HEADERS?: string;
  MAX_REQUESTS_PER_MINUTE?: string;
  MAX_REQUEST_BYTES_PER_MINUTE?: string;
  TOKEN_MIN_LENGTH?: string;
  TOKEN_MAX_LENGTH?: string;
}

interface CfInfo {
  country?: string;
  colo?: string;
  asn?: number;
  asOrganization?: string;
  city?: string;
  continent?: string;
  region?: string;
  regionCode?: string;
  timezone?: string;
  latitude?: string;
  longitude?: string;
  postalCode?: string;
  metroCode?: string;
  httpProtocol?: string;
  tlsVersion?: string;
  tlsCipher?: string;
}

export interface OobHit {
  hit_id: string;
  timestamp: string;
  token: string;
  event_type: "callback_hit" | "hits_query" | "admin_request";
  method: string;
  path: string;
  query: Record<string, string>;
  headers_present: string[];
  redacted_headers: string[];
  header_values: Record<string, string>;
  body_length: number;
  body_sha256: string;
  body_truncated: boolean;
  content_type: string;
  response_status?: number;
  response_location?: string;
  request_id?: string;
  trace_id?: string;
  cf_ray?: string;
  body_preview?: string;
  redirect_chain_id?: string;
  redirect_hop?: number;
  redirect_hops_total?: number;
  cf?: CfInfo;
}

interface OobStorage {
  hits: OobHit[];
}

interface RecentToken {
  token: string;
  last_seen: string;
  hit_count: number;
}

interface RecentTokenStorage {
  tokens: RecentToken[];
}

const RECENT_TOKENS_KEY = "recent:tokens";
const MAX_RECENT_TOKENS = 50;
const RESPONSE_PLAN_PREFIX = "response-plan:";
const RESPONSE_PLAN_INDEX = "response-plans:recent";
const MAX_RESPONSE_PLAN_BODY_BYTES = 8 * 1024;
const MAX_RESPONSE_PLAN_HOPS = 8;
const RESPONSE_PLAN_TTL_SECONDS = 24 * 60 * 60;

interface ResponseSpec {
  status: number;
  content_type: string;
  headers: Record<string, string>;
  body: string;
}

interface ResponsePlan {
  start_token: string;
  callback_token: string;
  final_token: string;
  redirect_hops: number;
  redirect_status: number;
  destination: string;
  get: ResponseSpec;
  head: ResponseSpec;
  created_at: string;
  expires_at: string;
  max_uses: number;
  uses: number;
  allow_http: boolean;
  allowed_hosts: string[];
}

const FORBIDDEN_RESPONSE_HEADERS = new Set([
  "connection", "content-length", "host", "location", "proxy-authenticate",
  "proxy-authorization", "set-cookie", "te", "trailer", "transfer-encoding", "upgrade",
]);

function hasCrlf(value: string): boolean {
  return CRLF_RE.test(value);
}

function getEnvConfig(env: OobEnv) {
  const intVal = (raw: string | undefined, fallback: number): number => {
    const parsed = Number(raw);
    if (!Number.isFinite(parsed) || !Number.isInteger(parsed) || parsed <= 0) return fallback;
    return parsed;
  };

  return {
    hitTtlSeconds: intVal(env.HIT_TTL_SECONDS, DEFAULTS.hitTtlSeconds),
    maxHitsPerToken: intVal(env.MAX_HITS_PER_TOKEN, DEFAULTS.maxHitsPerToken),
    maxBodyBytes: intVal(env.MAX_BODY_BYTES, DEFAULTS.maxBodyBytes),
    maxBodyPreviewBytes: intVal(env.MAX_BODY_PREVIEW_BYTES, DEFAULTS.maxBodyPreviewBytes),
    maxRedirectHops: intVal(env.MAX_REDIRECT_HOPS, DEFAULTS.maxRedirectHops),
    maxDelayMs: intVal(env.MAX_DELAY_MS, DEFAULTS.maxDelayMs),
    maxResponseBytes: intVal(env.MAX_RESPONSE_BYTES, DEFAULTS.maxResponseBytes),
    maxResponseHeaders: intVal(env.MAX_RESPONSE_HEADERS, DEFAULTS.maxResponseHeaders),
    maxRequestsPerMinute: intVal(
      env.MAX_REQUESTS_PER_MINUTE || env.MAX_REQUEST_BYTES_PER_MINUTE,
      DEFAULTS.maxRequestsPerMinute,
    ),
    minTokenLength: intVal(env.TOKEN_MIN_LENGTH, DEFAULTS.minTokenLength),
    maxTokenLength: intVal(env.TOKEN_MAX_LENGTH, DEFAULTS.maxTokenLength),
  };
}

function parseToken(raw: string | null, config: ReturnType<typeof getEnvConfig>): string | null {
  if (!raw) return null;
  const token = raw.trim();
  if (token.length < config.minTokenLength || token.length > config.maxTokenLength) return null;
  if (!EVENT_TOKEN_RE.test(token)) return null;
  return token;
}

function hasCrlfOrInvalid(header: string): boolean {
  return hasCrlf(header);
}

function isSensitiveHeader(name: string): boolean {
  const lower = name.toLowerCase();
  if (lower === "authorization" || lower === "cookie" || lower === "set-cookie") return true;
  if (lower.startsWith("proxy-")) return true;
  return /(token|secret|key|session)/i.test(lower);
}

function collectHeaders(request: Request): {
  names: string[];
  redacted: string[];
  values: Record<string, string>;
} {
  const names: string[] = [];
  const redacted: string[] = [];
  const values: Record<string, string> = {};

  request.headers.forEach((value, name) => {
    const lower = name.toLowerCase();
    names.push(lower);
    if (isSensitiveHeader(lower) && !HEADER_VALUE_ALLOWLIST.has(lower)) {
      values[lower] = REDACT_VALUE;
      redacted.push(lower);
      return;
    }
    if (hasCrlfOrInvalid(value)) {
      values[lower] = "[INVALID]";
      return;
    }
    values[lower] = value;
  });

  names.sort();
  redacted.sort();
  return { names, redacted, values };
}

function safeToken(token: string): string {
  if (token.length <= 8) return token;
  return `${token.slice(0, 4)}…${token.slice(-4)}`;
}

function constantTimeEqual(a: string, b: string): boolean {
  const ab = ENCODER.encode(a);
  const bb = ENCODER.encode(b);
  const max = Math.max(ab.length, bb.length);
  let diff = ab.length ^ bb.length;
  for (let i = 0; i < max; i++) {
    diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  }
  return diff === 0;
}

function isAdminRequest(request: Request, env: OobEnv): boolean {
  if (!env.ADMIN_TOKEN) return false;
  const header = env.ADMIN_TOKEN_HEADER || "authorization";
  const value = request.headers.get(header);
  if (!value) return false;
  const candidate = value.replace(/^Bearer\s+/i, "").trim();
  return constantTimeEqual(candidate, env.ADMIN_TOKEN);
}

function toCfInfo(request: Request): CfInfo | undefined {
  const raw = (request as Request & { cf?: CfInfo }).cf;
  if (!raw) return undefined;
  return {
    country: raw.country,
    colo: raw.colo,
    asn: raw.asn,
    asOrganization: raw.asOrganization,
    city: raw.city,
    continent: raw.continent,
    region: raw.region,
    regionCode: raw.regionCode,
    timezone: raw.timezone,
    latitude: raw.latitude,
    longitude: raw.longitude,
    postalCode: raw.postalCode,
    metroCode: raw.metroCode,
    httpProtocol: raw.httpProtocol,
    tlsVersion: raw.tlsVersion,
    tlsCipher: raw.tlsCipher,
  };
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function readBody(
  request: Request,
  maxBodyBytes: number,
  maxBodyPreviewBytes: number,
): Promise<{ length: number; preview: string; sha256: string; truncated: boolean }> {
  const method = request.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
    return { length: 0, preview: "", sha256: "", truncated: false };
  }

  const reader = request.body?.getReader();
  if (!reader) {
    return { length: 0, preview: "", sha256: "", truncated: false };
  }

  let total = 0;
  let truncated = false;
  const preview: number[] = [];
  const chunks: Uint8Array[] = [];

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;

    const captured = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    total += value.length;
    if (captured < maxBodyBytes) {
      chunks.push(value.slice(0, maxBodyBytes - captured));
    }
    if (total > maxBodyBytes) truncated = true;

    if (preview.length < maxBodyPreviewBytes) {
      const remaining = maxBodyPreviewBytes - preview.length;
      const take = Math.min(remaining, value.length);
      preview.push(...value.slice(0, take));
    }
  }

  if (chunks.length === 0) {
    return { length: total, preview: "", sha256: "", truncated };
  }

  const all = new Uint8Array(chunks.reduce((sum, c) => sum + c.length, 0));
  let offset = 0;
  for (const c of chunks) {
    all.set(c, offset);
    offset += c.length;
  }

  return {
    length: total,
    preview: new TextDecoder().decode(new Uint8Array(preview)).slice(0, maxBodyPreviewBytes),
    sha256: await sha256Hex(all),
    truncated,
  };
}

async function checkRateLimit(env: OobEnv, request: Request, limit: number): Promise<boolean> {
  if (!env.OOB || limit <= 0) return true;
  const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
  const bucket = ip.includes(":") ? ip.split(":").slice(0, 3).join(":") + "::" : ip.split(".").slice(0, 3).join(".") + ".0";
  const key = `rl:${bucket}`;

  const now = Date.now();
  const state = await env.OOB.get<{ windowStart: number; count: number }>(key, "json");
  const windowStart = state?.windowStart || now;
  const count = state?.count || 0;

  if (now - windowStart > RATE_WINDOW_SECONDS * 1000) {
    await env.OOB.put(key, JSON.stringify({ windowStart: now, count: 1 }), { expirationTtl: RATE_WINDOW_SECONDS });
    return true;
  }

  if (count >= limit) {
    return false;
  }

  await env.OOB.put(key, JSON.stringify({ windowStart, count: count + 1 }), { expirationTtl: RATE_WINDOW_SECONDS });
  return true;
}

async function readStorage(env: OobEnv, token: string): Promise<OobHit[]> {
  if (!env.OOB) return [];
  try {
    const stored = await env.OOB.get<OobStorage>(`hits:${token}`, "json");
    return stored?.hits || [];
  } catch {
    return [];
  }
}

async function writeStorage(env: OobEnv, token: string, ttlSeconds: number, hits: OobHit[]): Promise<void> {
  if (!env.OOB) return;
  await env.OOB.put(`hits:${token}`, JSON.stringify({ hits }), { expirationTtl: ttlSeconds });
}

function maskedLogEntry(hit: OobHit): void {
  logEntry({
    ...baseLog(new Request("https://hooks.invalid/log")),
    event: hit.event_type,
    hit_id: hit.hit_id,
    token: safeToken(hit.token),
    method: hit.method,
    path: hit.path,
    redirect_chain_id: hit.redirect_chain_id,
    redirect_hop: hit.redirect_hop,
    body_length: hit.body_length,
    body_truncated: hit.body_truncated,
    content_type: hit.content_type,
  });
}

async function recordHit(env: OobEnv, config: ReturnType<typeof getEnvConfig>, hit: OobHit): Promise<void> {
  maskedLogEntry(hit);
  if (!env.OOB) return;
  const prior = await readStorage(env, hit.token);
  const deduped = [hit, ...prior].filter((entry, idx, arr) => arr.findIndex((x) => x.hit_id === entry.hit_id) === idx);
  deduped.sort((a, b) => (a.timestamp > b.timestamp ? -1 : 1));
  const limited = deduped.slice(0, config.maxHitsPerToken);
  await writeStorage(env, hit.token, config.hitTtlSeconds, limited);

  if (hit.event_type === "callback_hit") {
    const stored = await env.OOB.get<RecentTokenStorage>(RECENT_TOKENS_KEY, "json");
    const previous = stored?.tokens || [];
    const existing = previous.find((entry) => entry.token === hit.token);
    const recent = [
      { token: hit.token, last_seen: hit.timestamp, hit_count: (existing?.hit_count || 0) + 1 },
      ...previous.filter((entry) => entry.token !== hit.token),
    ].slice(0, MAX_RECENT_TOKENS);
    await env.OOB.put(RECENT_TOKENS_KEY, JSON.stringify({ tokens: recent }), {
      expirationTtl: config.hitTtlSeconds,
    });
  }
}

async function buildRecord(
  request: Request,
  token: string,
  eventType: OobHit["event_type"],
  config: ReturnType<typeof getEnvConfig>,
  responseStatus?: number,
): Promise<OobHit> {
  const url = new URL(request.url);
  const headers = collectHeaders(request);
  const body = await readBody(request, config.maxBodyBytes, config.maxBodyPreviewBytes);
  const query: Record<string, string> = {};
  url.searchParams.forEach((value, key) => {
    if (hasCrlfOrInvalid(key) || hasCrlfOrInvalid(value)) return;
    query[key.slice(0, 128)] = value.slice(0, 2048);
  });

  const chainId = url.searchParams.get("oob_chain_id") ?? undefined;
  const hop = Number(url.searchParams.get("oob_redirect_hop") || NaN);
  const hops = Number(url.searchParams.get("oob_hops") || NaN);

  const hitId = crypto.randomUUID();
  const cfRay = request.headers.get("cf-ray") || undefined;
  const traceparent = request.headers.get("traceparent")?.split("-");
  const traceId = traceparent?.length === 4 ? traceparent[1] : undefined;

  return {
    hit_id: hitId,
    timestamp: new Date().toISOString(),
    token,
    event_type: eventType,
    method: request.method.toUpperCase(),
    path: `${url.pathname}${url.search}`,
    query,
    headers_present: headers.names,
    redacted_headers: headers.redacted,
    header_values: headers.values,
    body_length: body.length,
    body_sha256: `${BODY_SHA_PREFIX}${body.sha256 || "0"}`,
    body_truncated: body.truncated,
    body_preview: body.preview || undefined,
    content_type: request.headers.get("content-type") || "application/octet-stream",
    response_status: responseStatus,
    request_id: request.headers.get("x-request-id") || cfRay || hitId,
    trace_id: traceId,
    cf_ray: cfRay,
    redirect_chain_id: chainId,
    redirect_hop: Number.isFinite(hop) ? hop : undefined,
    redirect_hops_total: Number.isFinite(hops) ? hops : undefined,
    cf: toCfInfo(request),
  };
}

function safePublicHit(hit: OobHit): Record<string, unknown> {
  return {
    event_type: hit.event_type,
    hit_id: hit.hit_id,
    token: safeToken(hit.token),
    timestamp: hit.timestamp,
    method: hit.method,
    path: hit.path,
    headers_present: hit.headers_present,
    redacted_headers: hit.redacted_headers,
    body_length: hit.body_length,
    body_sha256: hit.body_sha256,
    content_type: hit.content_type,
    redirect_chain_id: hit.redirect_chain_id,
    redirect_hop: hit.redirect_hop,
    redirect_hops_total: hit.redirect_hops_total,
  };
}

function jsonResponse(payload: unknown, status = 200): Response {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function addRateLimitHeaders(response: Response, remaining: number, limit: number): Response {
  response.headers.set("X-RateLimit-Limit", String(limit));
  response.headers.set("X-RateLimit-Remaining", String(remaining));
  response.headers.set("X-RateLimit-Reset", String(Math.floor(Date.now() / 1000) + RATE_WINDOW_SECONDS));
  return response;
}

function isSafeStatus(raw: string | null, fallback: number): number {
  if (raw === null || raw === "") return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed)) return fallback;
  return Math.max(200, Math.min(599, Math.floor(parsed)));
}

function parseRedirectStatus(raw: string | null, fallback: number): number {
  const parsed = Number(raw);
  if (!SAFE_RESPONSE_STATUS.has(parsed)) return fallback;
  return parsed;
}

function parseIntParam(raw: string | null, fallback: number, min = 1, max = 100000): number {
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || !Number.isInteger(parsed)) return fallback;
  return Math.max(min, Math.min(max, parsed));
}

function validateRedirectTarget(raw: string | null, origin: string): string | Response {
  if (!raw) return jsonResponse({ error: "missing to parameter" }, 400);
  let target: URL;

  try {
    target = new URL(raw);
  } catch {
    return jsonResponse({ error: "invalid to parameter" }, 400);
  }

  if (!ALLOWED_REDIRECT_SCHEMES.test(target.protocol)) {
    return jsonResponse({ error: "unsafe redirect scheme" }, 400);
  }
  if (target.protocol === "javascript:" || target.protocol === "file:" || target.protocol === "data:") {
    return jsonResponse({ error: "unsafe redirect scheme" }, 400);
  }

  return target.toString();
}

function addResponseHeaders(url: URL, maxHeaders: number): Headers {
  const headers = new Headers();
  let used = 0;

  for (const [key, value] of url.searchParams.entries()) {
    if (!key.startsWith("header-")) continue;
    if (used >= maxHeaders) break;
    const name = key.slice("header-".length);

    if (hasCrlfOrInvalid(name) || hasCrlfOrInvalid(value)) continue;
    if (!SAFE_RESPONSE_HEADERS.has(name.toLowerCase())) continue;

    headers.append(name, value);
    used += 1;
  }

  return headers;
}

function safeCookies(raw: string | null): string[] {
  if (!raw) return [];
  return raw
    .split(",")
    .map((c) => c.trim())
    .filter((c) => c.length > 0 && !hasCrlfOrInvalid(c) && c.length <= 120)
    .filter((c) => /^[^;\s]+=.*/.test(c));
}

function sanitizeBody(raw: string, maxBytes: number): string {
  return new TextDecoder().decode(ENCODER.encode(raw || "").slice(0, maxBytes));
}

function validateJsonpCallback(callback: string | null): boolean {
  if (!callback) return false;
  if (hasCrlfOrInvalid(callback)) return false;
  if (callback.length > 64) return false;
  return SAFE_JSONP_CALLBACK.test(callback);
}

function redirectHopTarget(raw: string, state: { chainId: string; hop: number; maxHops: number }, request: Request): string {
  const target = new URL(raw);
  target.searchParams.set("oob_chain_id", state.chainId);
  target.searchParams.set("oob_redirect_hop", String(state.hop));
  target.searchParams.set("oob_hops", String(state.maxHops));
  target.searchParams.set("oob_probe_method", request.method.toUpperCase());
  target.searchParams.set("oob_probe_cookie", request.headers.has("cookie") ? "1" : "0");
  target.searchParams.set("oob_probe_marker", request.headers.has("x-research-marker") ? "1" : "0");
  target.searchParams.set("oob_probe_probe", request.headers.has("x-codex-probe") ? "1" : "0");
  return target.toString();
}

function isRedirectLoop(to: URL, state: { chainId: string; hop: number }): boolean {
  if (to.pathname.startsWith("/redirect/")) {
    const targetHop = Number(to.searchParams.get("oob_redirect_hop") || NaN);
    const targetChain = to.searchParams.get("oob_chain_id");
    return targetChain === state.chainId && targetHop >= state.hop;
  }
  return false;
}

async function safeResponseFromQuery(
  request: Request,
  config: ReturnType<typeof getEnvConfig>,
  defaults: { status?: number; contentType?: string; body?: string } = {},
): Promise<Response> {
  const url = new URL(request.url);
  const status = isSafeStatus(url.searchParams.get("status"), defaults.status || 200);
  const delayMs = parseIntParam(url.searchParams.get("ms"), 0, 0, config.maxDelayMs);
  const callback = url.searchParams.get("callback");
  const body = sanitizeBody(url.searchParams.get("body") || defaults.body || "", config.maxResponseBytes);
  const contentType = url.searchParams.get("content_type") || defaults.contentType || "text/plain";

  if (!SAFE_RESPONSE_CONTENT_TYPES.has(contentType)) {
    return jsonResponse({ error: "unsafe content type" }, 400);
  }

  const responseHeaders = addResponseHeaders(url, config.maxResponseHeaders);
  responseHeaders.set("Cache-Control", "no-store");
  responseHeaders.set("X-Content-Type-Options", "nosniff");

  if (delayMs > 0) {
    await new Promise((r) => setTimeout(r, delayMs));
  }

  const cookieHeader = url.searchParams.get("cookies");
  for (const c of safeCookies(cookieHeader)) {
    responseHeaders.append("Set-Cookie", c);
  }

  if (callback) {
    if (!validateJsonpCallback(callback)) {
      return jsonResponse({ error: "invalid callback" }, 400);
    }
    responseHeaders.set("Content-Type", "application/javascript; charset=utf-8");
    return new Response(`${callback}(${body})`, {
      status,
      headers: responseHeaders,
    });
  }

  responseHeaders.set("Content-Type", contentType);
  return new Response(body, { status, headers: responseHeaders });
}

function extractTokenFromRoute(request: Request): { token: string; eventType: OobHit["event_type"] } | null {
  const url = new URL(request.url);
  const pathParts = url.pathname.split("/").filter(Boolean);

  if (url.pathname.startsWith("/json/") || url.pathname.startsWith("/js/") || url.pathname.startsWith("/respond/") || url.pathname.startsWith("/delay/") || url.pathname.startsWith("/redirect/") || url.pathname.startsWith("/redirect-chain/")) {
    const token = pathParts[1] || "";
    return { token, eventType: "admin_request" };
  }

  if (pathParts[0] && ROUTE_PREFIXES.has(pathParts[0])) {
    if (pathParts[1] && pathParts[1] !== "hits" && pathParts[1] !== "admin") {
      return { token: pathParts[1].replace(/\.(gif|png|js|json|txt)$/i, ""), eventType: "callback_hit" };
    }
  }

  return null;
}

function extractToken(request: Request, config: ReturnType<typeof getEnvConfig>): { token: string; eventType: OobHit["event_type"] } | null {
  const found = extractTokenFromRoute(request);
  if (found?.token) {
    const token = parseToken(found.token, config);
    if (token) return { token, eventType: found.eventType === "admin_request" ? "admin_request" : "callback_hit" };
  }

  const hostParts = new URL(request.url).hostname.split(".");
  if (hostParts.length >= 3) {
    const token = parseToken(hostParts[0], config);
    if (token) return { token, eventType: "callback_hit" };
  }

  const url = new URL(request.url);
  const queryToken = parseToken(url.searchParams.get("token") || url.searchParams.get("t"), config);
  if (queryToken) return { token: queryToken, eventType: "callback_hit" };

  return null;
}

function parseTimeFilter(raw: string | null | undefined): number | undefined {
  if (!raw) return undefined;
  const t = Date.parse(raw);
  return Number.isNaN(t) ? undefined : t;
}

function filterHits(
  hits: OobHit[],
  options: {
    eventType?: string | null;
    hitId?: string | null;
    since?: string | null;
    until?: string | null;
  },
) {
  const eventType = options.eventType;
  const hitId = options.hitId;
  const since = parseTimeFilter(options.since);
  const until = parseTimeFilter(options.until);

  return hits.filter((hit) => {
    if (eventType && hit.event_type !== eventType) return false;
    if (hitId && hit.hit_id !== hitId) return false;
    const ts = Date.parse(hit.timestamp);
    if (since !== undefined && ts < since) return false;
    if (until !== undefined && ts > until) return false;
    return true;
  });
}

function validateResponseHeaders(raw: unknown): Record<string, string> | Response {
  if (raw === undefined) return {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return jsonResponse({ error: "headers must be an object" }, 400);
  const headers: Record<string, string> = {};
  const entries = Object.entries(raw as Record<string, unknown>);
  if (entries.length > DEFAULTS.maxResponseHeaders) return jsonResponse({ error: `at most ${DEFAULTS.maxResponseHeaders} response headers are allowed` }, 400);
  for (const [name, value] of entries) {
    const lower = name.toLowerCase();
    if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(lower) || FORBIDDEN_RESPONSE_HEADERS.has(lower) || lower.startsWith("cf-") || lower.startsWith("sec-")) {
      return jsonResponse({ error: `response header ${name} is not allowed` }, 400);
    }
    if (typeof value !== "string" || hasCrlf(value) || value.length > 2048) return jsonResponse({ error: `invalid value for response header ${name}` }, 400);
    headers[lower] = value;
  }
  return headers;
}

function validateResponseSpec(raw: unknown, fallback: ResponseSpec): ResponseSpec | Response {
  if (raw === undefined) return fallback;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return jsonResponse({ error: "response settings must be an object" }, 400);
  const input = raw as Record<string, unknown>;
  const status = Number(input.status ?? fallback.status);
  if (!Number.isInteger(status) || status < 200 || status > 599) return jsonResponse({ error: "response status must be between 200 and 599" }, 400);
  const contentType = String(input.content_type ?? fallback.content_type);
  if (!SAFE_RESPONSE_CONTENT_TYPES.has(contentType)) return jsonResponse({ error: "response Content-Type is not allowed" }, 400);
  const body = String(input.body ?? fallback.body);
  if (ENCODER.encode(body).length > MAX_RESPONSE_PLAN_BODY_BYTES) return jsonResponse({ error: `response body exceeds ${MAX_RESPONSE_PLAN_BODY_BYTES} bytes` }, 400);
  const headers = validateResponseHeaders(input.headers);
  if (headers instanceof Response) return headers;
  return { status, content_type: contentType, headers, body };
}

function responseFromSpec(spec: ResponseSpec, method: string): Response {
  const headers = new Headers(spec.headers);
  headers.set("Content-Type", spec.content_type);
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");
  return new Response(method === "HEAD" ? null : spec.body, { status: spec.status, headers });
}

function publicPlan(plan: ResponsePlan, origin: string) {
  return { ...plan, get: { ...plan.get, body: plan.get.body }, head: { ...plan.head, body: "" }, public_url: `${origin}/r/${plan.start_token}` };
}

async function updatePlanIndex(env: OobEnv, plan: ResponsePlan | null, removeToken = ""): Promise<void> {
  const stored = await env.OOB?.get<{ tokens: string[] }>(RESPONSE_PLAN_INDEX, "json");
  let tokens = (stored?.tokens || []).filter((token) => token !== removeToken && token !== plan?.start_token);
  if (plan) tokens = [plan.start_token, ...tokens].slice(0, MAX_RECENT_TOKENS);
  await env.OOB?.put(RESPONSE_PLAN_INDEX, JSON.stringify({ tokens }), { expirationTtl: RESPONSE_PLAN_TTL_SECONDS });
}

async function manageResponsePlans(request: Request, env: OobEnv, config: ReturnType<typeof getEnvConfig>): Promise<Response> {
  if (!isAdminRequest(request, env)) return jsonResponse({ error: "missing or invalid admin credentials" }, 401);
  if (!env.OOB) return jsonResponse({ error: "storage unavailable" }, 501);
  const url = new URL(request.url);
  const id = url.pathname.split("/").filter(Boolean)[3] || "";
  if (request.method === "GET") {
    if (id) {
      const plan = await env.OOB.get<ResponsePlan>(`${RESPONSE_PLAN_PREFIX}${id}`, "json");
      return plan ? jsonResponse(publicPlan(plan, url.origin)) : jsonResponse({ error: "response preset not found" }, 404);
    }
    const index = await env.OOB.get<{ tokens: string[] }>(RESPONSE_PLAN_INDEX, "json");
    const plans = (await Promise.all((index?.tokens || []).map((token) => env.OOB?.get<ResponsePlan>(`${RESPONSE_PLAN_PREFIX}${token}`, "json")))).filter(Boolean).map((plan) => publicPlan(plan as ResponsePlan, url.origin));
    return jsonResponse({ count: plans.length, presets: plans });
  }
  if (request.method === "DELETE") {
    const token = parseToken(id, config); if (!token) return jsonResponse({ error: "valid preset ID required" }, 400);
    await env.OOB.delete(`${RESPONSE_PLAN_PREFIX}${token}`); await updatePlanIndex(env, null, token);
    return jsonResponse({ deleted: true, start_token: token });
  }
  if (request.method !== "POST" && request.method !== "PUT") return jsonResponse({ error: "method not allowed" }, 405);
  let input: Record<string, unknown>;
  try { input = await request.json<Record<string, unknown>>(); } catch { return jsonResponse({ error: "invalid JSON body" }, 400); }
  const existing = request.method === "PUT" ? await env.OOB.get<ResponsePlan>(`${RESPONSE_PLAN_PREFIX}${id}`, "json") : null;
  if (request.method === "PUT" && !existing) return jsonResponse({ error: "response preset not found" }, 404);
  const startToken = parseToken(String(existing?.start_token || input.start_token || ""), config);
  const callbackToken = parseToken(String(existing?.callback_token || input.callback_token || ""), config);
  const finalToken = parseToken(String(existing?.final_token || input.final_token || ""), config);
  if (!startToken || !callbackToken || !finalToken) return jsonResponse({ error: "valid start, callback, and final tokens are required" }, 400);
  const redirectHops = Number(input.redirect_hops ?? 0);
  if (!Number.isInteger(redirectHops) || redirectHops < 0 || redirectHops > MAX_RESPONSE_PLAN_HOPS) return jsonResponse({ error: `redirect_hops must be between 0 and ${MAX_RESPONSE_PLAN_HOPS}` }, 400);
  const redirectStatus = Number(input.redirect_status ?? 302);
  if (redirectHops > 0 && !SAFE_RESPONSE_STATUS.has(redirectStatus)) return jsonResponse({ error: "redirect status must be 301, 302, 303, 307, or 308" }, 400);
  let destination = String(input.destination || "");
  if (redirectHops > 0) {
    const validated = validateRedirectTarget(destination, new URL(request.url).origin);
    if (validated instanceof Response) return validated;
    destination = validated;
    const parsed = new URL(destination);
    const allowHTTP = input.allow_http === true;
    if (parsed.protocol !== "https:" && !allowHTTP) return jsonResponse({ error: "redirect destinations must use HTTPS unless allow_http is explicitly enabled" }, 400);
    const allowedHosts = Array.isArray(input.allowed_hosts) ? input.allowed_hosts.map(String).map((host) => host.toLowerCase().trim()).filter(Boolean) : [];
    if (allowedHosts.length > 20 || allowedHosts.some((host) => !/^[a-z0-9.-]+$/.test(host))) return jsonResponse({ error: "invalid hostname allowlist" }, 400);
    if (allowedHosts.length && !allowedHosts.includes(parsed.hostname.toLowerCase())) return jsonResponse({ error: "redirect destination hostname is not allowlisted" }, 400);
  }
  const defaultSpec: ResponseSpec = { status: 200, content_type: "text/plain; charset=utf-8", headers: {}, body: "ok" };
  const get = validateResponseSpec(input.get, defaultSpec); if (get instanceof Response) return get;
  const head = validateResponseSpec(input.head, { ...get, body: "" }); if (head instanceof Response) return head;
  const ttl = Math.min(RESPONSE_PLAN_TTL_SECONDS, Math.max(60, Number(input.expires_in_seconds || RESPONSE_PLAN_TTL_SECONDS)));
  const maxUses = Math.min(1000, Math.max(1, Number(input.max_uses || existing?.max_uses || 20)));
  if (!Number.isInteger(ttl) || !Number.isInteger(maxUses)) return jsonResponse({ error: "expiry and maximum uses must be integers" }, 400);
  const now = new Date();
  const plan: ResponsePlan = { start_token: startToken, callback_token: callbackToken, final_token: finalToken, redirect_hops: redirectHops, redirect_status: redirectStatus, destination, get, head, created_at: existing?.created_at || now.toISOString(), expires_at: new Date(now.getTime() + ttl * 1000).toISOString(), max_uses: maxUses, uses: existing?.uses || 0, allow_http: input.allow_http === true, allowed_hosts: Array.isArray(input.allowed_hosts) ? input.allowed_hosts.map(String) : [] };
  await env.OOB.put(`${RESPONSE_PLAN_PREFIX}${startToken}`, JSON.stringify(plan), { expirationTtl: ttl });
  await updatePlanIndex(env, plan);
  return jsonResponse({ ...publicPlan(plan, url.origin), expires_in_seconds: ttl });
}

async function serveResponsePlan(request: Request, env: OobEnv, config: ReturnType<typeof getEnvConfig>): Promise<Response> {
  if (!env.OOB) return jsonResponse({ error: "storage unavailable" }, 501);
  if (request.method !== "GET" && request.method !== "HEAD") return jsonResponse({ error: "method not allowed" }, 405);
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean);
  const startToken = parseToken(parts[1] || "", config);
  const hop = Number(parts[2] || "0");
  if (!startToken || !Number.isInteger(hop) || hop < 0 || hop > MAX_RESPONSE_PLAN_HOPS) return jsonResponse({ error: "invalid response capability" }, 400);
  const plan = await env.OOB.get<ResponsePlan>(`${RESPONSE_PLAN_PREFIX}${startToken}`, "json");
  if (!plan) return jsonResponse({ error: "response capability not found or expired" }, 404);
  plan.expires_at ||= new Date(Date.parse(plan.created_at) + RESPONSE_PLAN_TTL_SECONDS * 1000).toISOString();
  plan.max_uses ||= 20;
  plan.uses ||= 0;
  if (Date.parse(plan.expires_at) <= Date.now()) return jsonResponse({ error: "response capability expired" }, 410);
  if (hop === 0) {
    if (plan.uses >= plan.max_uses) return jsonResponse({ error: "response capability maximum use count reached" }, 410);
    plan.uses += 1;
    const remaining = Math.max(60, Math.floor((Date.parse(plan.expires_at) - Date.now()) / 1000));
    await env.OOB.put(`${RESPONSE_PLAN_PREFIX}${startToken}`, JSON.stringify(plan), { expirationTtl: remaining });
  }
  const location = plan.redirect_hops > hop ? (hop + 1 < plan.redirect_hops ? `${url.origin}/r/${plan.start_token}/${hop + 1}` : plan.destination) : undefined;
  const hit = await buildRecord(request, plan.callback_token, "callback_hit", config, plan.redirect_hops > hop ? plan.redirect_status : (request.method === "HEAD" ? plan.head.status : plan.get.status));
  hit.response_location = location;
  hit.redirect_chain_id = plan.start_token;
  hit.redirect_hop = hop + 1;
  hit.redirect_hops_total = plan.redirect_hops + 1;
  await recordHit(env, config, hit);
  if (plan.redirect_hops > hop) {
    return new Response(null, { status: plan.redirect_status, headers: { Location: location!, "Cache-Control": "no-store", "X-Route": "response-plan" } });
  }
  return responseFromSpec(request.method === "HEAD" ? plan.head : plan.get, request.method);
}

export async function handleOob(request: Request, env: OobEnv): Promise<Response | null> {
  const url = new URL(request.url);
  const method = request.method.toUpperCase();
  const config = getEnvConfig(env);

  if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(method)) {
    return jsonResponse({ error: "method not allowed" }, 405);
  }

  const authenticatedConsoleRead = method === "GET" && isAdminRequest(request, env) && (
    url.pathname === "/oob/admin/tokens" ||
    url.pathname === "/oob/admin/hits" ||
    url.pathname === "/oob/admin/responses" ||
    url.pathname.startsWith("/oob/admin/responses/")
  );
  const allowed = authenticatedConsoleRead || await checkRateLimit(env, request, config.maxRequestsPerMinute);
  if (!allowed) {
    return addRateLimitHeaders(jsonResponse({ error: "rate limit exceeded" }, 429), 0, config.maxRequestsPerMinute);
  }

  if (url.pathname === "/oob/admin/responses" || url.pathname.startsWith("/oob/admin/responses/")) return manageResponsePlans(request, env, config);
  if (url.pathname.startsWith("/r/")) return serveResponsePlan(request, env, config);

  if (url.pathname === "/oob/hits") {
    if (method !== "GET") return jsonResponse({ error: "method not allowed" }, 405);

    const token = parseToken(url.searchParams.get("token"), config);
    if (!token) return jsonResponse({ error: "pass ?token=<unguessable-token>" }, 400);

    const hits = env.OOB ? await readStorage(env, token) : [];
    const filtered = filterHits(hits, {
      eventType: url.searchParams.get("event_type"),
      hitId: url.searchParams.get("hit_id"),
      since: url.searchParams.get("since"),
      until: url.searchParams.get("until"),
    }).filter((hit) => hit.event_type !== "hits_query");

    if (env.OOB) {
      await recordHit(env, config, await buildRecord(request, token, "hits_query", config));
      return jsonResponse({ token, event_type: "hits_query", count: filtered.length, hits: filtered.map(safePublicHit) });
    }

    return jsonResponse({ token, stored: false, error: "no KV binding" }, 501);
  }

  if (url.pathname === "/oob/admin/tokens") {
    if (method !== "GET") return jsonResponse({ error: "method not allowed" }, 405);
    if (!isAdminRequest(request, env)) return jsonResponse({ error: "missing or invalid admin credentials" }, 401);
    if (!env.OOB) return jsonResponse({ error: "storage unavailable" }, 501);

    const limit = parseIntParam(url.searchParams.get("limit"), 10, 1, MAX_RECENT_TOKENS);
    const stored = await env.OOB.get<RecentTokenStorage>(RECENT_TOKENS_KEY, "json");
    const tokens = (stored?.tokens || []).slice(0, limit);
    return jsonResponse({ event_type: "recent_tokens", count: tokens.length, tokens });
  }

  if (url.pathname === "/oob/admin/hits") {
    if (!isAdminRequest(request, env)) return jsonResponse({ error: "missing or invalid admin credentials" }, 401);

    const token = parseToken(url.searchParams.get("token"), config);
    if (!token) return jsonResponse({ error: "pass ?token=<token>" }, 400);

    if (method === "DELETE") {
      if (!env.OOB) return jsonResponse({ error: "storage unavailable" }, 501);
      const hitId = url.searchParams.get("hit_id");
      if (hitId) {
        const existing = await readStorage(env, token);
        const remaining = existing.filter((hit) => hit.hit_id !== hitId);
        await writeStorage(env, token, config.hitTtlSeconds, remaining);
      } else {
        await env.OOB.delete(`hits:${token}`);
        const stored = await env.OOB.get<RecentTokenStorage>(RECENT_TOKENS_KEY, "json");
        const recent = (stored?.tokens || []).filter((entry) => entry.token !== token);
        await env.OOB.put(RECENT_TOKENS_KEY, JSON.stringify({ tokens: recent }), {
          expirationTtl: config.hitTtlSeconds,
        });
      }
      maskedLogEntry(await buildRecord(request, token, "admin_request", config));
      return jsonResponse({ token, deleted: true });
    }

    if (method !== "GET") return jsonResponse({ error: "method not allowed" }, 405);
    if (!env.OOB) return jsonResponse({ error: "storage unavailable" }, 501);

    const hits = await readStorage(env, token);
    const filtered = filterHits(hits, {
      eventType: url.searchParams.get("event_type"),
      hitId: url.searchParams.get("hit_id"),
      since: url.searchParams.get("since"),
      until: url.searchParams.get("until"),
    });

    await recordHit(env, config, await buildRecord(request, token, "admin_request", config));
    return jsonResponse({ token, event_type: "admin_request", count: filtered.length, hits: filtered });
  }

  if (url.pathname.startsWith("/redirect-chain/")) {
    if (!isAdminRequest(request, env)) return jsonResponse({ error: "missing or invalid admin credentials" }, 401);

    const token = parseToken(url.pathname.split("/").filter(Boolean)[1], config);
    if (!token) return jsonResponse({ error: "invalid token" }, 400);

    const redirectTarget = validateRedirectTarget(url.searchParams.get("to"), url.origin);
    if (redirectTarget instanceof Response) return redirectTarget;

    const status = parseRedirectStatus(url.searchParams.get("status"), 302);
    const hops = parseIntParam(url.searchParams.get("hops"), config.maxRedirectHops, 1, config.maxRedirectHops);
    const chainId = crypto.randomUUID();

    const next = new URL(`/redirect/${token}`, url.origin);
    next.searchParams.set("to", redirectTarget);
    next.searchParams.set("status", String(status));
    next.searchParams.set("oob_chain_id", chainId);
    next.searchParams.set("oob_redirect_hop", "1");
    next.searchParams.set("oob_hops", String(hops));

    await recordHit(env, config, await buildRecord(request, token, "admin_request", config));
    return new Response(null, { status, headers: { Location: next.toString(), "X-Route": "redirect-chain" } });
  }

  if (url.pathname.startsWith("/redirect/")) {
    if (!isAdminRequest(request, env)) return jsonResponse({ error: "missing or invalid admin credentials" }, 401);

    const token = parseToken(url.pathname.split("/").filter(Boolean)[1], config);
    if (!token) return jsonResponse({ error: "invalid token" }, 400);

    const redirectTarget = validateRedirectTarget(url.searchParams.get("to"), url.origin);
    if (redirectTarget instanceof Response) return redirectTarget;

    const status = parseRedirectStatus(url.searchParams.get("status"), 302);
    const state = {
      chainId: url.searchParams.get("oob_chain_id") || crypto.randomUUID(),
      hop: parseIntParam(url.searchParams.get("oob_redirect_hop"), 1),
      maxHops: parseIntParam(url.searchParams.get("oob_hops"), config.maxRedirectHops, 1, config.maxRedirectHops),
    };

    const withMeta = redirectHopTarget(redirectTarget, state, request);
    const metaUrl = new URL(withMeta);

    if (state.hop >= state.maxHops || isRedirectLoop(metaUrl, { chainId: state.chainId, hop: state.hop })) {
      await recordHit(env, config, await buildRecord(request, token, "admin_request", config));
      return new Response(null, { status, headers: { Location: withMeta, "X-Route": "redirect" } });
    }

    if (state.hop > config.maxRedirectHops) {
      return jsonResponse({ error: "redirect hop limit exceeded" }, 400);
    }

    const next = new URL(`/redirect/${token}`, url.origin);
    next.searchParams.set("to", withMeta);
    next.searchParams.set("status", String(status));
    next.searchParams.set("oob_chain_id", state.chainId);
    next.searchParams.set("oob_redirect_hop", String(state.hop + 1));
    next.searchParams.set("oob_hops", String(state.maxHops));

    await recordHit(env, config, await buildRecord(request, token, "admin_request", config));
    return new Response(null, { status, headers: { Location: next.toString(), "X-Route": "redirect" } });
  }

  if (url.pathname.startsWith("/respond/")) {
    if (!isAdminRequest(request, env)) return jsonResponse({ error: "missing or invalid admin credentials" }, 401);
    const token = parseToken(url.pathname.split("/").filter(Boolean)[1], config);
    if (!token) return jsonResponse({ error: "invalid token" }, 400);
    await recordHit(env, config, await buildRecord(request, token, "admin_request", config));
    return safeResponseFromQuery(request, config, { contentType: "text/plain", body: "{}" });
  }

  if (url.pathname.startsWith("/delay/")) {
    if (!isAdminRequest(request, env)) return jsonResponse({ error: "missing or invalid admin credentials" }, 401);
    const token = parseToken(url.pathname.split("/").filter(Boolean)[1], config);
    if (!token) return jsonResponse({ error: "invalid token" }, 400);
    await recordHit(env, config, await buildRecord(request, token, "admin_request", config));
    return safeResponseFromQuery(request, config, {
      contentType: url.searchParams.get("content_type") || "text/plain",
      body: "",
    });
  }

  if (url.pathname.startsWith("/json/") || url.pathname.startsWith("/js/")) {
    const token = parseToken(url.pathname.split("/").filter(Boolean)[1], config);
    if (!token) return jsonResponse({ error: "invalid token" }, 400);

    const defaultBody = JSON.stringify({ ok: true, token: safeToken(token), timestamp: new Date().toISOString() });
    const response = await safeResponseFromQuery(
      request,
      config,
      {
        status: 200,
        contentType: url.pathname.startsWith("/json/") ? "application/json" : "application/javascript",
        body: defaultBody,
      },
    );
    await recordHit(env, config, await buildRecord(request, token, "callback_hit", config, response.status));
    return response;
  }

  const found = extractToken(request, config);
  if (!found) return null;

  const hit = await buildRecord(request, found.token, found.eventType, config, 200);
  await recordHit(env, config, hit);

  if (/\.(gif|png)$/i.test(url.pathname)) {
    return new Response(PIXEL_GIF, {
      headers: {
        "Content-Type": "image/gif",
        "X-Route": "oob-pixel",
      },
    });
  }

  if (/\.js$/i.test(url.pathname)) {
    return new Response(`/* callback ${hit.hit_id} */`, {
      headers: {
        "Content-Type": "application/javascript",
        "X-Route": "oob-js",
      },
    });
  }

  return jsonResponse({
    ok: true,
    event_type: hit.event_type,
    token: safeToken(hit.token),
    hit_id: hit.hit_id,
    path: hit.path,
  });
}

export function isSafeJsonpCallback(callback: string): boolean {
  return validateJsonpCallback(callback);
}

export function isResponseContentType(contentType: string): boolean {
  return SAFE_RESPONSE_CONTENT_TYPES.has(contentType);
}
