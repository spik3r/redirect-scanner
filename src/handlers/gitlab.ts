import { TARGETS } from "../lib/targets";
import { baseLog, logEntry } from "../lib/log";
import type { LogEntry } from "../lib/types";

let current = 0;

export function statusRoute(log: LogEntry): Response {
  const next = TARGETS[current];
  logEntry({ ...log, event: "gitlab:status", position: current, total: TARGETS.length });
  return jsonResponse({
    current,
    total: TARGETS.length,
    next: `${next.ip}:${next.port} (${next.label})`,
    targets: TARGETS.map((t) => `${t.ip}:${t.port} ${t.label}`),
  });
}

export function scanRoute(log: LogEntry): Response {
  const target = TARGETS[current];
  const dest = `http://${target.ip}:${target.port}/api/v4/projects.yml`;
  const pos = current;
  current = (current + 1) % TARGETS.length;
  const next = TARGETS[current];

  logEntry({
    ...log,
    event: "gitlab:redirect",
    position: pos + 1,
    total: TARGETS.length,
    target: `${target.ip}:${target.port}`,
    ip: target.label,
    next: `${next.ip}:${next.port} (${next.label})`,
    destination: dest,
  });

  return Response.redirect(dest, 302);
}

export function resetRoute(log: LogEntry): Response {
  const wasAt = current;
  current = 0;
  logEntry({ ...log, event: "gitlab:reset", position: 0, wasAt, total: TARGETS.length });
  return jsonResponse({ status: "reset", wasAt, total: TARGETS.length });
}

export function targetsRoute(log: LogEntry): Response {
  logEntry({ ...log, event: "gitlab:targets", total: TARGETS.length });
  return jsonResponse(
    TARGETS.map((t, i) => ({
      id: i + 1,
      ip: t.ip,
      port: t.port,
      label: t.label,
      url: `http://${t.ip}:${t.port}/api/v4/projects.yml`,
    }))
  );
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

export function handleGitlab(request: Request): Response | null {
  const url = new URL(request.url);
  const path = url.pathname;
  const log = baseLog(request);

  if (path === "/gitlab/scan.yml") return scanRoute(log);
  if (path === "/gitlab/status") return statusRoute(log);
  if (path === "/gitlab/reset") return resetRoute(log);
  if (path === "/gitlab/targets") return targetsRoute(log);

  return null;
}
