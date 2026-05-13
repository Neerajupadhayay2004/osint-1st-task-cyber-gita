import { createServerFn } from "@tanstack/react-start";

export type IocBundle = {
  ips: string[];
  domains: string[];
  emails: string[];
  hashes: string[];
  cves: string[];
  urls: string[];
};

const RX = {
  ip: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g,
  hash: /\b[a-f0-9]{32,64}\b/gi,
  cve: /CVE-\d{4}-\d{4,7}/gi,
  url: /https?:\/\/[^\s,;"'<>()]+/gi,
};

export function extractIocs(text: string): IocBundle {
  const norm = text.replace(/\[\.\]|\(\.\)/g, ".");
  const uniq = (arr: string[]) => Array.from(new Set(arr.map((s) => s.trim()).filter(Boolean)));
  const urls = uniq(norm.match(RX.url) ?? []);
  const emails = uniq(norm.match(RX.email) ?? []);
  const ips = uniq(norm.match(RX.ip) ?? []).filter((ip) => {
    const p = ip.split(".").map(Number);
    return p.every((n) => n >= 0 && n <= 255);
  });
  const cves = uniq((norm.match(RX.cve) ?? []).map((s) => s.toUpperCase()));
  const hashes = uniq(norm.match(RX.hash) ?? []);
  // Strip emails / urls before matching domains so we don't double-count
  const stripped = norm
    .replace(RX.email, " ")
    .replace(RX.url, " ");
  const domains = uniq((stripped.match(RX.domain) ?? []))
    .filter((d) => !ips.includes(d) && d.includes("."))
    .map((d) => d.toLowerCase());
  return { ips, domains, emails, hashes, cves, urls };
}

async function ipBatch(ips: string[]) {
  if (!ips.length) return [];
  try {
    const r = await fetch("http://ip-api.com/batch?fields=status,country,city,isp,org,query,proxy,hosting", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(ips.slice(0, 50).map((q) => ({ query: q }))),
    });
    if (!r.ok) return [];
    return await r.json();
  } catch { return []; }
}

async function abuseCheck(ip: string) {
  const key = process.env.ABUSEIPDB_API_KEY;
  if (!key) return null;
  try {
    const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { Key: key, Accept: "application/json" },
    });
    if (!r.ok) return null;
    const j: any = await r.json();
    return j?.data ? { score: j.data.abuseConfidenceScore, reports: j.data.totalReports, country: j.data.countryCode } : null;
  } catch { return null; }
}

async function callAi(prompt: string) {
  const key = process.env.LOVABLE_API_KEY;
  if (key) {
    try {
      const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
        body: JSON.stringify({
          model: "google/gemini-2.5-flash",
          messages: [
            { role: "system", content: "You are an elite SOC analyst. Produce concise, technical IOC triage reports in markdown. Always include sections: Executive Summary, Risk Rating (Low/Medium/High/Critical with justification), Notable Indicators, Per-IOC Notes, Recommended Actions." },
            { role: "user", content: prompt },
          ],
          temperature: 0.3,
        }),
      });
      const j: any = await r.json();
      if (r.ok) return { ok: true as const, text: j?.choices?.[0]?.message?.content || "", model: "gemini-2.5-flash" };
    } catch {}
  }
  const gk = process.env.GEMINI_API_KEY;
  if (gk) {
    try {
      const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${gk}`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.3, maxOutputTokens: 4096 } }),
      });
      const j: any = await r.json();
      if (r.ok) return { ok: true as const, text: j?.candidates?.[0]?.content?.parts?.map((p: any) => p.text).join("") || "", model: "gemini-2.0-flash" };
    } catch {}
  }
  return { ok: false as const, error: "AI unavailable" };
}

export const analyzeIocs = createServerFn({ method: "POST" })
  .inputValidator((d: { text: string; filename?: string }) => d)
  .handler(async ({ data }) => {
    if (!data.text || data.text.length > 200_000) {
      return { ok: false as const, error: "Empty or too large (max 200KB)" };
    }
    const iocs = extractIocs(data.text);
    const total = iocs.ips.length + iocs.domains.length + iocs.emails.length + iocs.hashes.length + iocs.cves.length + iocs.urls.length;
    if (total === 0) return { ok: false as const, error: "No IOCs detected (IPs, domains, emails, hashes, CVEs, URLs)." };

    // Enrich: ip-api batch + abuseipdb (parallel, capped)
    const [geo, abuse] = await Promise.all([
      ipBatch(iocs.ips),
      Promise.all(iocs.ips.slice(0, 10).map((ip) => abuseCheck(ip).then((d) => ({ ip, ...(d ?? {}) })))),
    ]);

    const enrichment = {
      ip_geo: geo,
      ip_abuse: abuse.filter((a: any) => a.score !== undefined),
    };

    const prompt = [
      data.filename ? `Source file: ${data.filename}` : "Source: pasted IOC list",
      `Detected indicators (sample, capped):`,
      iocs.ips.length ? `IPs (${iocs.ips.length}): ${iocs.ips.slice(0, 30).join(", ")}` : "",
      iocs.domains.length ? `Domains (${iocs.domains.length}): ${iocs.domains.slice(0, 30).join(", ")}` : "",
      iocs.emails.length ? `Emails (${iocs.emails.length}): ${iocs.emails.slice(0, 20).join(", ")}` : "",
      iocs.hashes.length ? `Hashes (${iocs.hashes.length}): ${iocs.hashes.slice(0, 20).join(", ")}` : "",
      iocs.cves.length ? `CVEs (${iocs.cves.length}): ${iocs.cves.slice(0, 30).join(", ")}` : "",
      iocs.urls.length ? `URLs (${iocs.urls.length}): ${iocs.urls.slice(0, 20).join(", ")}` : "",
      "",
      "Live enrichment data (JSON):",
      "```json",
      JSON.stringify(enrichment, null, 2).slice(0, 8000),
      "```",
      "",
      "Produce a consolidated triage report. Group by indicator type. Call out suspicious geos, hosting providers, high abuse scores, known-bad ASNs, and any CVEs that are exploited in the wild. Recommend which CyberGita modules to pivot into (/ip-domain, /shodan, /virustotal, /cve-search).",
    ].filter(Boolean).join("\n");

    const ai = await callAi(prompt);
    if (!ai.ok) return { ok: false as const, error: ai.error, iocs };
    return { ok: true as const, iocs, enrichment, summary: ai.text, model: ai.model, total };
  });
