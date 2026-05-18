import type { LogEntry } from "./types";

export function ts(): string {
  return new Date().toISOString();
}

export function baseLog(request: Request): LogEntry {
  const ua = request.headers.get("User-Agent") || "unknown";
  let cfInfo: Record<string, unknown> = { colo: "?", country: "?", asn: 0 };
  try {
    const raw = (request as unknown as Record<string, unknown>).cf as Record<string, unknown> || {};
    cfInfo = {
      colo: raw.colo || "?",
      country: raw.country || "?",
      asn: Number(raw.asn) || 0,
    };
  } catch {
    /* CF metadata not available in dev */
  }
  return {
    ts: ts(),
    event: "request",
    ua: ua.substring(0, 80),
    cf: cfInfo,
  };
}

export function logEntry(entry: LogEntry): void {
  console.log(JSON.stringify(entry));
}
