import { describe, expect, it } from "vitest";
import worker from "../src/index";
import { fixtureDefinitions, handleFixture } from "../src/handlers/fixtures";

const origin = "https://hooks.mement0rq.com";
const fixtureCases = [
  ["/fixtures/valid-gif-correct-mime.gif", "image/gif", [0x47, 0x49, 0x46, 0x38]],
  ["/fixtures/valid-gif-no-extension", "image/gif", [0x47, 0x49, 0x46, 0x38]],
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
    const png = new Uint8Array(await handleFixture(new Request(origin + fixtureCases[6][0]))!.arrayBuffer());
    expect([...png.slice(16, 24)]).toEqual([0, 0, 0, 1, 0, 0, 0, 1]);
    const svg = await handleFixture(new Request(origin + fixtureCases[7][0]))!.text();
    expect(svg).toContain("<rect"); expect(svg).toContain("<text");
    expect(svg).not.toMatch(/<script|onload|href=|animate/i);
  });

  it("serves fixed no-extension and cross-host redirects for every status", async () => {
    const targets = {
      "valid-gif-final-no-extension": "/fixtures/valid-gif-no-extension",
      "cross-host-valid-gif": "https://fixtures-alt.mement0rq.com/fixtures/valid-gif-correct-mime.gif",
    };
    for (const status of [301, 302, 303, 307, 308]) for (const [name, location] of Object.entries(targets)) {
      for (const method of ["GET", "HEAD"]) {
        const response = handleFixture(new Request(`${origin}/fixtures/redirect/${status}/${name}.gif`, { method }));
        expect(response?.status).toBe(status); expect(response?.headers.get("location")).toBe(location);
        expect((await response!.arrayBuffer()).byteLength).toBe(0);
      }
    }
  });

  it("serves deterministic oEmbed discovery pages and GET/HEAD JSON cases", async () => {
    const cases = ["safe", "special-title", "html-canaries", "malformed", "wrong-mime"];
    for (const name of cases) {
      const pagePath = `/fixtures/oembed/page/${name}`;
      const page = handleFixture(new Request(origin + pagePath))!;
      const pageHead = handleFixture(new Request(origin + pagePath, { method: "HEAD" }))!;
      const pageBody = await page.text();
      expect(page.headers.get("content-type")).toBe("text/html; charset=utf-8");
      expect(pageBody).toContain(`type="application/json+oembed"`);
      expect(pageBody).toContain(`href="${origin}/fixtures/oembed/json/${name}"`);
      expect((await pageHead.arrayBuffer()).byteLength).toBe(0);
      expect([...pageHead.headers]).toEqual([...page.headers]);

      const jsonPath = `/fixtures/oembed/json/${name}`;
      const response = handleFixture(new Request(origin + jsonPath))!;
      const head = handleFixture(new Request(origin + jsonPath, { method: "HEAD" }))!;
      const body = await response.text();
      expect((await head.arrayBuffer()).byteLength).toBe(0);
      expect([...head.headers]).toEqual([...response.headers]);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("x-content-type-options")).toBe("nosniff");
      expect(response.headers.get("content-type")).toBe(name === "wrong-mime" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8");
      if (name === "malformed") expect(() => JSON.parse(body)).toThrow();
      else {
        const value = JSON.parse(body);
        expect(value).toMatchObject({ version: "1.0", type: "rich", provider_name: "Mement0rq Fixtures", provider_url: origin, width: 640, height: 360 });
        if (name === "special-title") expect(value.title).toBe('Mement0rq "quotes" <angles> & ampersand — 雪 🌱');
        if (name === "html-canaries") {
          expect(value.html).toContain("MEMENT0RQ_HTML_CANARY_20260915");
          expect(value.html).toContain("MEMENT0RQ_SCRIPT_CANARY_20260915");
          expect(value.html).not.toMatch(/<script|src=|href=/i);
        }
      }
    }
  });

  it("serves every fixed oEmbed redirect with exact locations", async () => {
    const cases = ["safe", "special-title", "html-canaries", "malformed", "wrong-mime"];
    for (const status of [301, 302, 303, 307, 308]) for (const name of cases) for (const kind of ["page", "json"]) for (const crossHost of [false, true]) {
      const prefix = crossHost ? "cross-host/" : "";
      const path = `/fixtures/oembed/redirect/${status}/${prefix}${kind}/${name}`;
      const location = `${crossHost ? "https://fixtures-alt.mement0rq.com" : ""}/fixtures/oembed/${kind}/${name}`;
      for (const method of ["GET", "HEAD"]) {
        const response = handleFixture(new Request(origin + path, { method }))!;
        expect(response.status).toBe(status);
        expect(response.headers.get("location")).toBe(location);
        expect((await response.arrayBuffer()).byteLength).toBe(0);
      }
    }
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
    const overviewBody = await overview?.text();
    expect(overviewBody).toContain("navigator.clipboard.writeText");
    expect(fixtureDefinitions).toHaveLength(160);
    for (const fixture of fixtureDefinitions) {
      expect(overviewBody).toContain(fixture.path);
      expect(overviewBody).toContain(fixture.description);
    }
    const deniedRedirect = handleFixture(new Request(`${origin}/fixtures/redirect/302/cross-host-valid-gif.gif`, { method: "POST" }));
    expect(deniedRedirect?.status).toBe(405);
    const deniedOembed = handleFixture(new Request(`${origin}/fixtures/oembed/json/safe`, { method: "POST", body: "not-read" }));
    expect(deniedOembed?.status).toBe(405);
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
