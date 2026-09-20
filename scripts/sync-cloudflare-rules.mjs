#!/usr/bin/env node

const API = "https://api.cloudflare.com/client/v4";
const zoneName = process.env.CLOUDFLARE_ZONE_NAME || "mement0rq.com";
const apiToken = process.env.MONSTERA_OOB_CLOUDFLARE_API_TOKEN || process.env.CLOUDFLARE_API_TOKEN || "";
const apply = process.argv.includes("--apply");

if (!apiToken) {
  throw new Error("MONSTERA_OOB_CLOUDFLARE_API_TOKEN or CLOUDFLARE_API_TOKEN is required (Zone WAF Read for checks; Zone WAF Write for --apply)");
}

async function cloudflare(path, init = {}) {
  const response = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      Authorization: `Bearer ${apiToken}`,
      "Content-Type": "application/json",
      ...init.headers,
    },
  });
  const body = await response.json();
  if (!response.ok || !body.success) {
    const details = (body.errors || []).map((error) => error.message).join("; ");
    throw new Error(`Cloudflare API ${response.status}: ${details || "request failed"}`);
  }
  return body.result;
}

async function zoneID() {
  if (process.env.CLOUDFLARE_ZONE_ID) return process.env.CLOUDFLARE_ZONE_ID;
  const zones = await cloudflare(`/zones?name=${encodeURIComponent(zoneName)}`);
  const zone = zones.find((candidate) => candidate.name === zoneName);
  if (!zone) throw new Error(`Cloudflare zone ${zoneName} was not found`);
  return zone.id;
}

async function entrypoint(zone, phase) {
  return cloudflare(`/zones/${zone}/rulesets/phases/${phase}/entrypoint`);
}

async function updateRule(zone, ruleset, current, desired) {
  const payload = current.ref ? { ...desired, ref: current.ref } : desired;
  const currentRateLimit = current.ratelimit ? {
    characteristics: current.ratelimit.characteristics,
    mitigation_timeout: current.ratelimit.mitigation_timeout,
    period: current.ratelimit.period,
    requests_per_period: current.ratelimit.requests_per_period,
  } : undefined;
  const changed = JSON.stringify({
    action: current.action,
    description: current.description,
    enabled: current.enabled !== false,
    expression: current.expression,
    ratelimit: currentRateLimit,
  }) !== JSON.stringify(desired);

  if (!changed) {
    console.log(`unchanged: ${desired.description}`);
    return;
  }
  if (!apply) {
    console.log(`would update: ${desired.description}`);
    console.log(JSON.stringify(payload, null, 2));
    return;
  }
  await cloudflare(`/zones/${zone}/rulesets/${ruleset.id}/rules/${current.id}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
  console.log(`updated: ${desired.description}`);
}

const zone = await zoneID();
const customRuleset = await entrypoint(zone, "http_request_firewall_custom");
const shortPathRule = customRuleset.rules.find((rule) => rule.description === "Block no-token OOB probes");
if (shortPathRule) {
  await updateRule(zone, customRuleset, shortPathRule, {
    action: shortPathRule.action,
    description: shortPathRule.description,
    enabled: false,
    expression: shortPathRule.expression,
  });
} else {
  console.log("unchanged: obsolete short-path rule is absent");
}

const rateRuleset = await entrypoint(zone, "http_ratelimit");
const rateRule = rateRuleset.rules.find((rule) => rule.description === "Flood protection on OOB endpoints");
if (!rateRule) throw new Error("Flood protection on OOB endpoints rule was not found; refusing to create an unreviewed duplicate");

const callbackExpression = [
  '(http.host eq "hooks.mement0rq.com" and (',
  'http.request.uri.path eq "/oob" or ',
  '(starts_with(http.request.uri.path, "/oob/") and not starts_with(http.request.uri.path, "/oob/admin/")) or ',
  'starts_with(http.request.uri.path, "/json/") or ',
  'starts_with(http.request.uri.path, "/js/") or ',
  'starts_with(http.request.uri.path, "/r/")',
  ')) or ends_with(http.host, ".hooks.mement0rq.com")',
].join("");

await updateRule(zone, rateRuleset, rateRule, {
  action: "block",
  description: "Flood protection on OOB endpoints",
  enabled: true,
  expression: callbackExpression,
  ratelimit: {
    characteristics: ["cf.colo.id", "ip.src"],
    mitigation_timeout: 10,
    period: 10,
    requests_per_period: 45,
  },
});

if (!apply) console.log("dry run only; pass --apply after reviewing the proposed changes");
