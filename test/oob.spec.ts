import { describe, expect, it } from "vitest";
import { handleOob } from "../src/handlers/oob";

interface MockKVGetOptions {
  type?: "json" | "text";
}

class MemoryKV {
  private store = new Map<string, string>();
  reads = 0;
  writes = 0;

  async get<T>(key: string, options?: MockKVGetOptions | "json" | "text"): Promise<T | null> {
    this.reads += 1;
    const value = this.store.get(key);
    if (!value) return null;
    if (options === "json" || (typeof options === "object" && options.type === "json")) {
      return JSON.parse(value) as T;
    }
    return (value as unknown) as T;
  }

  async put(key: string, value: string): Promise<void> {
    this.writes += 1;
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }
}

interface Env {
  OOB?: MemoryKV;
  ADMIN_TOKEN?: string;
  TOKEN_HMAC_SECRET?: string;
  REQUIRE_SIGNED_TOKENS?: string;
  SKIP_RATE_LIMIT?: string;
  SKIP_RECENT_TOKENS?: string;
  MAX_HITS_PER_TOKEN?: string;
  MAX_BODY_BYTES?: string;
  MAX_REQUESTS_PER_MINUTE?: string;
  MAX_REQUEST_BYTES_PER_MINUTE?: string;
  MAX_DELAY_MS?: string;
  MAX_RESPONSE_BYTES?: string;
  MAX_RESPONSE_HEADERS?: string;
}

function makeReq(path: string, init: RequestInit = {}): Request {
  const url = path.startsWith("http://") || path.startsWith("https://")
    ? path
    : `https://hooks.mement0rq.com${path}`;
  return new Request(url, init);
}

function makeEnv(): Env {
  return {
    OOB: new MemoryKV(),
    ADMIN_TOKEN: "admin-secret",
    MAX_HITS_PER_TOKEN: "2",
  } as Env;
}

function adminHeaders(): HeadersInit {
  return { Authorization: "Bearer admin-secret" };
}

function token(char: string): string {
  return `${char}`.repeat(24);
}

describe("oob callback routes", () => {
  it("does not write KV rate-limit state for authenticated console reads", async () => {
    const env = makeEnv();
    const kv = env.OOB as MemoryKV;
    const response = await handleOob(makeReq("/oob/admin/tokens?limit=50", { headers: adminHeaders() }), env as never);
    expect(response?.status).toBe(200);
    expect(kv.reads).toBe(1);
    expect(kv.writes).toBe(0);
  });

  it("classifies callback and polling events", async () => {
    const env = makeEnv();
    const id = token("a");

    await handleOob(makeReq(`/oob/${id}`), env as never);
    const query = await handleOob(makeReq(`/oob/hits?token=${id}`), env as never);
    const body = await query?.json();

    expect(body?.event_type).toBe("hits_query");
    expect(body?.hits?.[0]?.event_type).toBe("callback_hit");
  });

  it("redacts sensitive headers and preserves allowlist values", async () => {
    const env = makeEnv();
    const id = token("b");

    await handleOob(
      makeReq(`/oob/${id}`, {
        headers: {
          Authorization: "secret-token",
          Cookie: "session-id=abcd",
          "X-Research-Marker": "marker-1",
          "X-Codex-Probe": "probe-1",
        },
      }),
      env as never,
    );

    const raw = await handleOob(
      makeReq(`/oob/admin/hits?token=${id}`, {
        headers: { Authorization: "Bearer admin-secret" },
      }),
      env as never,
    );
    const body = await raw?.json();
    const hit = body?.hits?.[0];

    expect(hit?.redacted_headers).toEqual(expect.arrayContaining(["authorization", "cookie"]));
    expect(hit?.header_values?.authorization).toBe("[REDACTED]");
    expect(hit?.header_values?.cookie).toBe("[REDACTED]");
    expect(hit?.header_values?.["x-research-marker"]).toBe("marker-1");
    expect(hit?.header_values?.["x-codex-probe"]).toBe("probe-1");
  });

  it("stores request identity and safe Cloudflare metadata", async () => {
    const env = makeEnv();
    const id = token("z");
    const request = makeReq(`/oob/${id}`, {
      headers: {
        "CF-Connecting-IP": "192.0.2.10",
        "CF-Ray": "ray-id-SJC",
        "User-Agent": "fixture-agent",
        traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
      },
    });
    Object.defineProperty(request, "cf", { value: {
      asn: 2635, asOrganization: "Automattic, Inc", country: "US", city: "Los Angeles",
      colo: "SJC", httpProtocol: "HTTP/1.1", tlsVersion: "TLSv1.3", tlsCipher: "fixture",
    }});
    await handleOob(request, env as never);
    const raw = await handleOob(makeReq(`/oob/admin/hits?token=${id}`, { headers: adminHeaders() }), env as never);
    const hit = (await raw?.json())?.hits?.find((entry: { event_type: string }) => entry.event_type === "callback_hit");
    expect(hit?.request_id).toBe("ray-id-SJC");
    expect(hit?.trace_id).toBe("4bf92f3577b34da6a3ce929d0e0e4736");
    expect(hit?.response_status).toBe(200);
    expect(hit?.cf).toMatchObject({ asn: 2635, asOrganization: "Automattic, Inc", city: "Los Angeles", httpProtocol: "HTTP/1.1", tlsVersion: "TLSv1.3" });
  });

  it("provisions authenticated GET and HEAD response capabilities", async () => {
    const env = makeEnv();
    const payload = {
      start_token: token("s"), callback_token: token("c"), final_token: token("f"),
      max_uses: 2, expires_in_seconds: 3600,
      redirect_hops: 0, redirect_status: 302, destination: "",
      get: { status: 201, content_type: "application/json", headers: { "x-test": "get" }, body: '{"ok":true}' },
      head: { status: 204, content_type: "text/plain", headers: { "x-test": "head" }, body: "not-sent" },
    };
    const denied = await handleOob(makeReq("/oob/admin/responses", { method: "POST", body: JSON.stringify(payload) }), env as never);
    expect(denied?.status).toBe(401);
    const created = await handleOob(makeReq("/oob/admin/responses", { method: "POST", headers: { ...adminHeaders(), "content-type": "application/json" }, body: JSON.stringify(payload) }), env as never);
    const result = await created?.json();
    expect(created?.status).toBe(200);
    expect(JSON.stringify(result)).not.toContain("admin-secret");
    const get = await handleOob(makeReq(new URL(result.public_url).pathname), env as never);
    expect(get?.status).toBe(201); expect(get?.headers.get("x-test")).toBe("get"); expect(await get?.text()).toBe('{"ok":true}');
    const head = await handleOob(makeReq(new URL(result.public_url).pathname, { method: "HEAD" }), env as never);
    expect(head?.status).toBe(204); expect(head?.headers.get("x-test")).toBe("head"); expect(await head?.text()).toBe("");
    expect((await handleOob(makeReq(new URL(result.public_url).pathname), env as never))?.status).toBe(410);
  });

  it("serves bounded multi-hop response capabilities", async () => {
    const env = makeEnv();
    const payload = { start_token: token("u"), callback_token: token("v"), final_token: token("w"), redirect_hops: 2, redirect_status: 302, destination: `https://hooks.mement0rq.com/oob/${token("w")}`, get: { status: 200, content_type: "text/plain", headers: {}, body: "ok" }, head: { status: 200, content_type: "text/plain", headers: {}, body: "" } };
    const created = await handleOob(makeReq("/oob/admin/responses", { method: "POST", headers: { ...adminHeaders(), "content-type": "application/json" }, body: JSON.stringify(payload) }), env as never);
    const result = await created?.json(); const first = await handleOob(makeReq(new URL(result.public_url).pathname), env as never);
    expect(first?.status).toBe(302); expect(first?.headers.get("location")).toContain(`/r/${token("u")}/1`);
    const evidence = await handleOob(makeReq(`/oob/admin/hits?token=${payload.callback_token}`, { headers: adminHeaders() }), env as never);
    const redirectHit = (await evidence?.json())?.hits?.find((hit: { response_location?: string }) => hit.response_location);
    expect(redirectHit?.response_location).toContain(`/r/${token("u")}/1`);
    const second = await handleOob(makeReq(new URL(first?.headers.get("location") || "").pathname), env as never);
    expect(second?.headers.get("location")).toBe(payload.destination);
  });

  it("rejects unsafe response plans", async () => {
    const env = makeEnv();
    const base = { start_token: token("x"), callback_token: token("y"), final_token: token("z"), redirect_hops: 1, redirect_status: 302, destination: "javascript:alert(1)", get: { status: 200, content_type: "text/plain", headers: {}, body: "ok" }, head: { status: 200, content_type: "text/plain", headers: {}, body: "" } };
    const send = (value: unknown) => handleOob(makeReq("/oob/admin/responses", { method: "POST", headers: { ...adminHeaders(), "content-type": "application/json" }, body: JSON.stringify(value) }), env as never);
    expect((await send(base))?.status).toBe(400);
    expect((await send({ ...base, redirect_hops: 9, destination: "https://example.com" }))?.status).toBe(400);
    expect((await send({ ...base, destination: "http://example.com" }))?.status).toBe(400);
    expect((await send({ ...base, destination: "https://example.com", allowed_hosts: ["allowed.example"] }))?.status).toBe(400);
    expect((await send({ ...base, destination: "https://example.com", get: { ...base.get, headers: { "set-cookie": "secret=x" } } }))?.status).toBe(400);
    expect((await send({ ...base, destination: "https://example.com", get: { ...base.get, headers: { "x-test": "ok\r\ninjected: yes" } } }))?.status).toBe(400);
    expect((await send({ ...base, destination: "https://example.com", get: { ...base.get, body: "x".repeat(9000) } }))?.status).toBe(400);
  });

  it("lists, edits, and deletes response presets with admin authentication", async () => {
    const env = makeEnv(); const id = token("p");
    const payload = { start_token:id, callback_token:token("q"), final_token:token("r"), redirect_hops:1, redirect_status:301, destination:"https://hooks.mement0rq.com/final", allowed_hosts:["hooks.mement0rq.com"], max_uses:5, expires_in_seconds:600, get:{status:200,content_type:"text/plain",headers:{},body:"ok"}, head:{status:200,content_type:"text/plain",headers:{},body:""} };
    const auth = { ...adminHeaders(), "content-type":"application/json" };
    expect((await handleOob(makeReq("/oob/admin/responses",{method:"POST",headers:auth,body:JSON.stringify(payload)}),env as never))?.status).toBe(200);
    const listed = await handleOob(makeReq("/oob/admin/responses",{headers:adminHeaders()}),env as never); expect((await listed?.json())?.presets).toHaveLength(1);
    const edited = await handleOob(makeReq(`/oob/admin/responses/${id}`,{method:"PUT",headers:auth,body:JSON.stringify({...payload,redirect_status:308})}),env as never); expect((await edited?.json())?.redirect_status).toBe(308);
    expect((await handleOob(makeReq(`/oob/admin/responses/${id}`,{method:"DELETE",headers:adminHeaders()}),env as never))?.status).toBe(200);
    expect((await handleOob(makeReq(`/r/${id}`),env as never))?.status).toBe(404);
  });

  it("serves strict JSONP for /json and /js", async () => {
    const env = makeEnv();
    const id = token("c");

    const bad = await handleOob(makeReq(`/json/${id}?callback=bad name`), env as never);
    expect(bad?.status).toBe(400);

    const json = await handleOob(makeReq(`/json/${id}?callback=goodFn`), env as never);
    expect((await json?.text()) || "").toContain("goodFn(");

    const badJs = await handleOob(makeReq(`/js/${id}?callback=alert(1)`), env as never);
    expect(badJs?.status).toBe(400);

    const js = await handleOob(makeReq(`/js/${id}?callback=callbackFn`), env as never);
    expect((await js?.text()) || "").toContain("callbackFn(");
  });

  it("blocks unsafe redirect schemes", async () => {
    const env = makeEnv();
    const id = token("d");

    const unsafe = await handleOob(makeReq(`/redirect/${id}?to=javascript:alert(1)`, { headers: adminHeaders() }), env as never);
    expect(unsafe?.status).toBe(400);

    const unsafeChain = await handleOob(
      makeReq(`/redirect-chain/${id}?to=javascript:alert(1)&status=302`, { headers: adminHeaders() }),
      env as never,
    );
    expect(unsafeChain?.status).toBe(400);
  });

  it("supports all redirect status codes and hop metadata", async () => {
    const env = makeEnv();
    const id = token("e");

    for (const status of [301, 302, 303, 307, 308]) {
      const r = await handleOob(makeReq(`/redirect/${id}?to=https://example.com&status=${status}`, { headers: adminHeaders() }), env as never);
      expect(r?.status).toBe(status);
    }

    const chain = await handleOob(
      makeReq(`/redirect-chain/${id}?to=https://example.com&hops=2&status=307`, { headers: adminHeaders() }),
      env as never,
    );
    const first = chain?.headers.get("location") || "";
    expect(first.includes("/redirect/")).toBe(true);

    const second = await handleOob(makeReq(first, { headers: adminHeaders() }), env as never);
    const secondLoc = second?.headers.get("location") || "";
    expect(second?.status).toBe(307);
    expect(secondLoc).toContain("oob_redirect_hop=2");
    expect(secondLoc).toContain("oob_chain_id=");
  });

  it("records oversized bodies and preserves full length", async () => {
    const env = {
      ...makeEnv(),
      MAX_BODY_BYTES: "20",
    } as Env;
    const id = token("f");

    await handleOob(
      makeReq(`/oob/${id}`, {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: "x".repeat(40),
      }),
      env as never,
    );

    const admin = await handleOob(
      makeReq(`/oob/admin/hits?token=${id}`, {
        headers: { Authorization: "Bearer admin-secret" },
      }),
      env as never,
    );
    const body = await admin?.json();
    const hit = body?.hits?.find((h: { event_type: string }) => h.event_type === "callback_hit");
    expect(hit?.body_length).toBe(40);
    expect(hit?.body_truncated).toBe(true);
  });

  it("supports /respond and /delay controls", async () => {
    const env = {
      ...makeEnv(),
      MAX_DELAY_MS: "20",
      MAX_RESPONSE_BYTES: "32",
      MAX_RESPONSE_HEADERS: "2",
    } as Env;
    const id = token("g");

    const start = Date.now();
    const res = await handleOob(
      makeReq(
        `/respond/${id}?ms=10&status=201&content_type=application/json&body=%7B%22ok%22%3Atrue%7D&header-x-test=not-allowed&cookies=session%3Dok%2Cinvalid\\r\\n`,
        {
          headers: { Authorization: "Bearer admin-secret" },
        },
      ),
      env as never,
    );

    expect(res?.status).toBe(201);
    expect(res?.headers.get("content-type")).toBe("application/json");
    expect(Date.now() - start).toBeGreaterThanOrEqual(0);

    const delay = await handleOob(
      makeReq(`/delay/${id}?ms=5&content_type=text/plain&body=hello`, {
        headers: { Authorization: "Bearer admin-secret" },
      }),
      env as never,
    );
    expect(delay?.status).toBe(200);
  });

  it("supports token-scoped deletion and short retention", async () => {
    const env = {
      ...makeEnv(),
      MAX_HITS_PER_TOKEN: "2",
    } as Env;
    const id = token("h");

    await handleOob(makeReq(`/oob/${id}`), env as never);
    await handleOob(makeReq(`/oob/${id}`), env as never);
    await handleOob(makeReq(`/oob/${id}`), env as never);

    const before = await handleOob(
      makeReq(`/oob/admin/hits?token=${id}`, {
        headers: { Authorization: "Bearer admin-secret" },
      }),
      env as never,
    );
    expect((await before?.json())?.count).toBe(2);

    await handleOob(
      makeReq(`/oob/admin/hits?token=${id}`, {
        method: "DELETE",
        headers: { Authorization: "Bearer admin-secret" },
      }),
      env as never,
    );

    const after = await handleOob(
      makeReq(`/oob/admin/hits?token=${id}`, {
        headers: { Authorization: "Bearer admin-secret" },
      }),
      env as never,
    );
    expect((await after?.json())?.count).toBe(0);

    const recent = await handleOob(
      makeReq("/oob/admin/tokens", { headers: adminHeaders() }),
      env as never,
    );
    expect((await recent?.json())?.tokens).toEqual([]);
  });

  it("denies unauthorised raw log access", async () => {
    const env = makeEnv();
    const id = token("i");

    const denied = await handleOob(makeReq(`/oob/admin/hits?token=${id}`), env as never);
    expect(denied?.status).toBe(401);

    const deniedWrong = await handleOob(
      makeReq(`/oob/admin/hits?token=${id}`, { headers: { Authorization: "Bearer wrong" } }),
      env as never,
    );
    expect(deniedWrong?.status).toBe(401);
  });

  it("lists recently active callback tokens for admins", async () => {
    const env = { ...makeEnv(), SKIP_RECENT_TOKENS: "false" } as Env;
    const first = token("l");
    const second = token("m");

    await handleOob(makeReq(`/oob/${first}`), env as never);
    await handleOob(makeReq(`/oob/${second}`), env as never);
    await handleOob(makeReq(`/oob/${first}`), env as never);

    const response = await handleOob(
      makeReq("/oob/admin/tokens?limit=2", { headers: adminHeaders() }),
      env as never,
    );
    const body = await response?.json();

    expect(response?.status).toBe(200);
    expect(body?.tokens?.map((entry: { token: string }) => entry.token)).toEqual([first, second]);
    expect(body?.tokens?.[0]?.hit_count).toBe(2);

    const denied = await handleOob(makeReq("/oob/admin/tokens"), env as never);
    expect(denied?.status).toBe(401);
  });

  it("supports rate limits", async () => {
    const env = {
      ...makeEnv(),
      SKIP_RATE_LIMIT: "false",
      MAX_REQUEST_BYTES_PER_MINUTE: "1",
    } as Env;
    const id = token("j");

    const first = await handleOob(makeReq(`/oob/${id}`), env as never);
    const second = await handleOob(makeReq(`/oob/${id}`), env as never);

    expect(first?.status).toBe(200);
    expect(second?.status).toBe(429);
  });

  it("does no KV work for invalid callback tokens", async () => {
    const env = {
      ...makeEnv(),
      SKIP_RATE_LIMIT: "false",
      SKIP_RECENT_TOKENS: "false",
    } as Env;
    const kv = env.OOB as MemoryKV;

    const json = await handleOob(makeReq("/oob/too-short"), env as never);
    const pixel = await handleOob(makeReq("/oob/bad!.gif"), env as never);
    const query = await handleOob(makeReq("/oob?token=also-too-short"), env as never);
    const unrelated = await handleOob(makeReq("/not-a-collector-route"), env as never);

    expect(json?.status).toBe(400);
    expect(pixel?.status).toBe(200);
    expect(pixel?.headers.get("content-type")).toBe("image/gif");
    expect(query?.status).toBe(400);
    expect(unrelated).toBeNull();
    expect(kv.reads).toBe(0);
    expect(kv.writes).toBe(0);
  });

  it("accepts issued signed tokens and rejects forged valid-looking tokens without KV", async () => {
    const env = {
      ...makeEnv(),
      TOKEN_HMAC_SECRET: "test-secret-with-at-least-32-characters",
      REQUIRE_SIGNED_TOKENS: "true",
    } as Env;
    const kv = env.OOB as MemoryKV;

    const issuedResponse = await handleOob(
      makeReq("/oob/admin/tokens", {
        method: "POST",
        headers: { ...adminHeaders(), "content-type": "application/json" },
        body: JSON.stringify({ label: "ssrf-test" }),
      }),
      env as never,
    );
    const issued = (await issuedResponse?.json())?.token as string;

    expect(issued).toMatch(/^s1_ssrf-test-[a-f0-9]{16}_[a-f0-9]{32}$/);
    expect(kv.reads).toBe(0);
    expect(kv.writes).toBe(0);

    const forged = await handleOob(
      makeReq(`/oob/s1_ssrf-test-0000000000000000_${"0".repeat(32)}`),
      env as never,
    );
    expect(forged?.status).toBe(400);
    expect(kv.reads).toBe(0);
    expect(kv.writes).toBe(0);

    const accepted = await handleOob(makeReq(`/oob/${issued}`), env as never);
    expect(accepted?.status).toBe(200);

    const monsteraToken = "s1_oob-api-ex-71f90e77d14baf36_356fc8fd232fad4ca73fe7cc57659e86";
    const monsteraAccepted = await handleOob(makeReq(`/oob/${monsteraToken}`), {
      ...env,
      TOKEN_HMAC_SECRET: "12345678901234567890123456789012",
    } as never);
    expect(monsteraAccepted?.status).toBe(200);
    expect(kv.reads).toBe(2);
    expect(kv.writes).toBe(2);
  });

  it("skips rate-limit and recent-token KV operations by default", async () => {
    const env = makeEnv();
    const kv = env.OOB as MemoryKV;
    const id = token("n");

    await handleOob(makeReq(`/oob/${id}`), env as never);

    expect(kv.reads).toBe(1);
    expect(kv.writes).toBe(1);
  });

  it("keeps hit polling read-only in KV", async () => {
    const env = makeEnv();
    const kv = env.OOB as MemoryKV;
    const id = token("o");

    await handleOob(makeReq(`/oob/${id}`), env as never);
    const readsAfterCallback = kv.reads;
    const writesAfterCallback = kv.writes;

    await handleOob(makeReq(`/oob/hits?token=${id}`), env as never);

    expect(kv.reads).toBe(readsAfterCallback + 1);
    expect(kv.writes).toBe(writesAfterCallback);
  });

  it("stops rewriting KV after a token reaches its hit cap", async () => {
    const env = makeEnv();
    const kv = env.OOB as MemoryKV;
    const id = token("p");

    await handleOob(makeReq(`/oob/${id}`), env as never);
    await handleOob(makeReq(`/oob/${id}`), env as never);
    await handleOob(makeReq(`/oob/${id}`), env as never);

    expect(kv.reads).toBe(3);
    expect(kv.writes).toBe(2);
  });

  it("supports public filtering by hit id and event type", async () => {
    const env = makeEnv();
    const id = token("k");

    await handleOob(makeReq(`/oob/${id}`), env as never);
    await handleOob(makeReq(`/oob/${id}`), env as never);

    const admin = await handleOob(
      makeReq(`/oob/admin/hits?token=${id}`, {
        headers: { Authorization: "Bearer admin-secret" },
      }),
      env as never,
    );
    const adminBody = await admin?.json();
    const hitId = adminBody?.hits?.[0]?.hit_id;

    const query = await handleOob(
      makeReq(`/oob/hits?token=${id}&event_type=callback_hit&hit_id=${hitId}`),
      env as never,
    );
    const body = await query?.json();

    expect(body?.hits?.length).toBe(1);
    expect(body?.hits?.[0]?.event_type).toBe("callback_hit");
    expect(body?.hits?.[0]?.token).not.toBe(id);
  });
});
