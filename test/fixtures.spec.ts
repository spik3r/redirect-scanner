import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { fixtureDefinitions, handleFixture } from "../src/handlers/fixtures";

const origin = "https://hooks.mement0rq.com";
const fixtureCases = [
  ["/fixtures/valid-gif-correct-mime.gif", "image/gif", [0x47, 0x49, 0x46, 0x38]],
  ["/fixtures/valid-gif-octet-stream.gif", "application/octet-stream", [0x47, 0x49, 0x46, 0x38]],
  ["/fixtures/valid-gif-text-plain.gif", "text/plain", [0x47, 0x49, 0x46, 0x38]],
  ["/fixtures/invalid-gif-image-mime.gif", "image/gif", [0x4e, 0x4f, 0x54, 0x5f]],
  ["/fixtures/valid-gif-wrong-extension.txt", "image/gif", [0x47, 0x49, 0x46, 0x38]],
  ["/fixtures/valid-png-correct-mime.png", "image/png", [0x89, 0x50, 0x4e, 0x47]],
  ["/fixtures/svg-image.svg", "image/svg+xml", [0x3c, 0x73, 0x76, 0x67]],
  ["/fixtures/html-as-image.gif", "image/gif", [0x3c, 0x21, 0x64, 0x6f]],
  ["/fixtures/oversized-declared-gif.gif", "image/gif", [0x47, 0x49, 0x46, 0x38]],
] as const;

describe("public media fixtures", () => {
  it.each(fixtureCases)("serves GET and matching HEAD for %s", async (path, contentType, signature) => {
    const get = handleFixture(new Request(origin + path));
    const head = handleFixture(new Request(origin + path, { method: "HEAD" }));
    expect(get?.status).toBe(200);
    expect(head?.status).toBe(200);
    expect(get?.headers.get("content-type")).toBe(contentType);
    expect([...new Uint8Array(await get!.arrayBuffer()).slice(0, 4)]).toEqual(signature);
    expect((await head!.arrayBuffer()).byteLength).toBe(0);
    for (const name of ["content-type", "cache-control", "x-content-type-options", "x-mement0rq-fixture"]) {
      expect(head?.headers.get(name)).toBe(get?.headers.get(name));
    }
    expect(get?.headers.get("cache-control")).toBe("no-store");
    expect(get?.headers.get("x-content-type-options")).toBe("nosniff");
    expect(get?.headers.has("access-control-allow-origin")).toBe(false);
  });

  it("uses valid one-pixel image dimensions and harmless active-content-free SVG", async () => {
    const gif = new Uint8Array(await handleFixture(new Request(origin + fixtureCases[0][0]))!.arrayBuffer());
    expect([...gif.slice(6, 10)]).toEqual([1, 0, 1, 0]);
    const png = new Uint8Array(await handleFixture(new Request(origin + fixtureCases[5][0]))!.arrayBuffer());
    expect([...png.slice(16, 24)]).toEqual([0, 0, 0, 1, 0, 0, 0, 1]);
    const svg = await handleFixture(new Request(origin + fixtureCases[6][0]))!.text();
    expect(svg).toContain("<rect"); expect(svg).toContain("<text");
    expect(svg).not.toMatch(/<script|onload|href=|animate/i);
  });

  it("serves every fixed redirect for GET and HEAD", async () => {
    const targets = { "valid-gif": "/fixtures/valid-gif-correct-mime.gif", "gif-octet-stream": "/fixtures/valid-gif-octet-stream.gif", "invalid-gif": "/fixtures/invalid-gif-image-mime.gif" };
    for (const status of [301, 302, 303, 307, 308]) for (const [name, location] of Object.entries(targets)) {
      for (const suffix of ["", ".gif"]) for (const method of ["GET", "HEAD"]) {
        const response = handleFixture(new Request(`${origin}/fixtures/redirect/${status}/${name}${suffix}`, { method }));
        expect(response?.status).toBe(status); expect(response?.headers.get("location")).toBe(location);
        expect((await response!.arrayBuffer()).byteLength).toBe(0);
      }
    }
  });

  it("rejects unsupported methods and provides a copyable overview", async () => {
    const denied = handleFixture(new Request(origin + fixtureCases[0][0], { method: "POST" }));
    expect(denied?.status).toBe(405); expect(denied?.headers.get("allow")).toBe("GET, HEAD");
    const overview = handleFixture(new Request(origin + "/fixtures"));
    expect(await overview?.text()).toContain("navigator.clipboard.writeText");
    expect(fixtureDefinitions).toHaveLength(39);
  });

  it("bypasses KV and rate-limit storage in the full Worker", async () => {
    const calls: string[] = [];
    const env = { OOB: { get: async () => { calls.push("get"); return null; }, put: async () => { calls.push("put"); }, delete: async () => { calls.push("delete"); } } };
    for (const fixture of fixtureDefinitions) {
      const response = await worker.fetch(new Request(origin + fixture.path), env as never);
      expect(response.status).not.toBe(404);
    }
    expect(calls).toEqual([]);
  });
});
