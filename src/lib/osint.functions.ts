import { createServerFn } from "@tanstack/react-start";

const ok = <T,>(data: T) => ({ ok: true as const, data });
const fail = (error: string) => ({ ok: false as const, error });

// FastAPI Backend URL - adjust if your backend runs on a different port
const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000/api";

async function safeJson(url: string, init?: RequestInit) {
  const res = await fetch(url, init);
  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch { /* ignore */ }
  
  if (!res.ok) {
    // Check if it's our backend error or an external one
    const errorMsg = json?.detail || json?.message || `HTTP ${res.status}: ${text.slice(0, 200)}`;
    throw new Error(errorMsg);
  }
  return json;
}

function cleanDomain(input: string): string {
  let domain = input.trim().toLowerCase();
  // Remove protocols
  domain = domain.replace(/^(https?:\/\/)/, "");
  // Remove everything after the first slash
  domain = domain.split("/")[0];
  // Remove everything after the first question mark (if any before slash)
  domain = domain.split("?")[0];
  // Remove port numbers
  domain = domain.split(":")[0];
  return domain;
}

/* ----------------------------- AI helper (Lovable AI Gateway w/ Gemini fallback) ----------------------------- */
async function callLovableAI(prompt: string): Promise<{ ok: boolean; text?: string; error?: string }> {
  const key = process.env.LOVABLE_API_KEY;
  if (!key) return { ok: false, error: "LOVABLE_API_KEY missing" };
  try {
    const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${key}`,
      },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: "You are an expert OSINT/cybersecurity analyst. Always respond with valid JSON only." },
          { role: "user", content: prompt },
        ],
        response_format: { type: "json_object" },
      }),
    });
    const j: any = await r.json();
    if (!r.ok) return { ok: false, error: j?.error?.message || `HTTP ${r.status}` };
    const text = j?.choices?.[0]?.message?.content || "{}";
    return { ok: true, text };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

async function callGeminiDirect(prompt: string, model: string): Promise<{ ok: boolean; text?: string; error?: string; status?: number }> {
  const key = process.env.GEMINI_API_KEY;
  if (!key) return { ok: false, error: "GEMINI_API_KEY missing" };
  try {
    const r = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.3, maxOutputTokens: 8192, responseMimeType: "application/json" },
        }),
      }
    );
    const j: any = await r.json();
    if (!r.ok) return { ok: false, error: j?.error?.message || `HTTP ${r.status}`, status: r.status };
    const text = j?.candidates?.[0]?.content?.parts?.[0]?.text || "{}";
    return { ok: true, text };
  } catch (e: any) {
    return { ok: false, error: e.message };
  }
}

async function geminiAnalyze(prompt: string, rawData?: any) {
  // Try Lovable AI Gateway first (no quota issues, managed key)
  let res = await callLovableAI(prompt);

  // Fallback chain: try direct Gemini with successively cheaper/faster models
  if (!res.ok) {
    const models = ["gemini-2.5-flash", "gemini-2.5-flash-lite", "gemini-1.5-flash"];
    for (const m of models) {
      const direct = await callGeminiDirect(prompt, m);
      if (direct.ok) { res = direct; break; }
      // If quota error, brief backoff before next model
      if (direct.status === 429) await new Promise(r => setTimeout(r, 1500));
      res = direct;
    }
  }

  if (!res.ok || !res.text) {
    console.error("AI analysis failed:", res.error);
    return getFrontendFallback(rawData, res.error || "AI unavailable");
  }

  try {
    return JSON.parse(res.text);
  } catch {
    return { summary: res.text, recommendations: [], risk_assessment: res.text };
  }
}

function getFrontendFallback(rawData: any, errorMsg: string) {
  const malicious = (rawData?.vtStats?.malicious || 0) + (rawData?.vtStats?.suspicious || 0);
  const abuseScore = rawData?.abuseScore || 0;
  
  let risk = "Low";
  if (malicious > 0 || abuseScore > 20) risk = "Medium";
  if (malicious > 5 || abuseScore > 50) risk = "High";

  return {
    summary: `Automated Risk Verdict: ${risk} (AI Quota Exceeded)`,
    risk_assessment: `Heuristic analysis indicates a ${risk} threat level. Detected ${malicious} suspicious signals from reputation engines and an abuse score of ${abuseScore}/100.`,
    recommendations: [
      "Verify the target manually via Shodan/VirusTotal",
      "Monitor for unusual outbound connections",
      risk !== "Low" ? "Consider blocking this target at the firewall" : "Continue monitoring",
      "Update security feeds"
    ],
    technical_details: `AI Fallback triggered: ${errorMsg}`
  };
}

function isIp(v: string) { return /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(v) || v.includes(":"); }

/* ----------------------------- IP / Domain (unified) ----------------------------- */
export const lookupIp = createServerFn({ method: "POST" })
  .inputValidator((d: { query: string }) => d)
  .handler(async ({ data }) => {
    try {
      const q = cleanDomain(data.query);
      if (!q) return fail("Empty query");
      const target = q;
      const looksIp = isIp(q);

      // 1) Geo via ip-api (works for IP and domain)
      const geo = await safeJson(`http://ip-api.com/json/${encodeURIComponent(q)}?fields=66846719`)
        .catch(e => ({ status: "fail", message: e.message }));
      const ip = geo?.query || (looksIp ? q : null);

      // 2) Parallel: AbuseIPDB, VirusTotal, Shodan
      const [abuse, vt, shodan] = await Promise.all([
        ip ? safeJson(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`,
          { headers: { Key: process.env.ABUSEIPDB_API_KEY || "", Accept: "application/json" } }
        ).then(r => r?.data || r).catch(e => ({ error: e.message })) : Promise.resolve(null),
        safeJson(
          `https://www.virustotal.com/api/v3/${looksIp ? "ip_addresses" : "domains"}/${encodeURIComponent(looksIp ? (ip || q) : q)}`,
          { headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY || "", Accept: "application/json" } }
        ).then(r => r?.data || r).catch(e => ({ error: e.message })),
        ip ? safeJson(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${process.env.SHODAN_API_KEY || ""}`)
          .catch(e => ({ error: e.message })) : Promise.resolve(null),
      ]);

      // Build summary
      const vtStats = vt?.attributes?.last_analysis_stats || {};
      const malicious = (vtStats.malicious || 0) + (vtStats.suspicious || 0);
      const totalDetections = malicious;
      const abuseScore = abuse?.abuseConfidenceScore || 0;
      const isMalicious = malicious > 0 || abuseScore >= 50;
      const isWhitelisted = abuse?.isWhitelisted === true;
      const score = Math.min(1, (abuseScore / 100) * 0.6 + Math.min(malicious / 10, 1) * 0.4);
      const level = score >= 0.75 ? "critical" : score >= 0.4 ? "high" : score >= 0.15 ? "medium" : "low";

      const network = {
        isp: geo?.isp, org: geo?.org, asn: geo?.as,
        country: geo?.country, city: `${geo?.city || ""}${geo?.regionName ? ", " + geo.regionName : ""}`.trim().replace(/^,\s*/, ""),
        timezone: geo?.timezone, lat: geo?.lat, lon: geo?.lon,
        ports: shodan?.ports || [],
      };

      // 3) Gemini analysis
      const gem = await geminiAnalyze(
        `You are a SOC analyst. Analyze this OSINT data and return STRICT JSON with keys:
{"summary": "1-line verdict","risk_assessment":"2-3 sentence detailed risk paragraph","recommendations":["action 1","action 2","action 3","action 4"]}
Target: ${target}
Geo: ${JSON.stringify(network)}
AbuseIPDB: score=${abuseScore}, reports=${abuse?.totalReports || 0}, usage=${abuse?.usageType || "?"}
VirusTotal: malicious=${vtStats.malicious || 0}, suspicious=${vtStats.suspicious || 0}, harmless=${vtStats.harmless || 0}
Shodan ports: ${(shodan?.ports || []).join(",") || "none"}`,
        { vtStats, abuseScore }
      );

      const classifierThreat = isMalicious || score >= 0.4;
      return ok({
        target,
        summary: {
          is_malicious: isMalicious,
          is_whitelisted: isWhitelisted,
          threat_score: Number(score.toFixed(2)),
          threat_level: level,
          total_detections: totalDetections,
        },
        network,
        ai_intelligence: {
          classifier: {
            threat: classifierThreat,
            confidence: Math.max(0.6, score),
            text: classifierThreat
              ? `Suspicious indicators detected from ${malicious} VT vendor(s) and AbuseIPDB score ${abuseScore}.`
              : `No malicious signals across ${Object.keys(vtStats).length || 0} reputation engines.`,
          },
          gemini_report: gem.error ? { error: gem.error } : {
            summary: gem.summary || "Analysis complete.",
            risk_assessment: gem.risk_assessment || "",
            recommendations: gem.recommendations || [],
          },
        },
        raw_sources: { geo, abuse, virustotal: vt, shodan },
      });
    } catch (e: any) { return fail(e.message); }
  });

/* ----------------------------- Subdomains via crt.sh ----------------------------- */
export const lookupCertificates = createServerFn({ method: "POST" })
  .inputValidator((d: { domain: string }) => d)
  .handler(async ({ data }) => {
    try {
      const domain = cleanDomain(data.domain);
      if (!domain) return fail("Empty domain");
      const json = await safeJson(`https://crt.sh/?q=${encodeURIComponent("%." + domain)}&output=json`);
      const subs = new Set<string>();
      const certs: any[] = [];
      for (const r of json || []) {
        (r.name_value || "").split("\n").forEach((s: string) => subs.add(s.trim().toLowerCase()));
        certs.push({
          id: r.id,
          name: r.name_value,
          issuer: r.issuer_name,
          notBefore: r.not_before,
          notAfter: r.not_after,
        });
      }
      return ok({ subdomains: [...subs].slice(0, 200), certs: certs.slice(0, 50), total: certs.length });
    } catch (e: any) { return fail(e.message); }
  });

/* ----------------------------- Email Breach (XposedOrNot — free) ----------------------------- */
export const checkEmailBreach = createServerFn({ method: "POST" })
  .inputValidator((d: { email: string }) => d)
  .handler(async ({ data }) => {
    try {
      const email = data.email.trim().toLowerCase();
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail("Invalid email");
      
      // Call our backend
      try {
        const json = await safeJson(`${BACKEND_URL}/threat-intel/breaches/${encodeURIComponent(email)}`);
        return ok(json);
      } catch (backendError) {
        const breaches = await safeJson(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`)
          .catch(() => ({ ExposedBreaches: { breaches_details: [] } }));
        return ok(breaches);
      }
    } catch (e: any) { return fail(e.message); }
  });

/* ----------------------------- CVE Search (CIRCL) ----------------------------- */
export const searchCves = createServerFn({ method: "POST" })
  .inputValidator((d: { query: string }) => d)
  .handler(async ({ data }) => {
    try {
      const q = data.query.trim();
      if (!q) return fail("Empty query");
      
      // Call our backend
      try {
        const json = await safeJson(`${BACKEND_URL}/threat-intel/cves/search?query=${encodeURIComponent(q)}`);
        return ok({ items: json });
      } catch (backendError) {
        // Fallback to CIRCL directly
        const json = await safeJson(`https://cve.circl.lu/api/search/${encodeURIComponent(q)}`);
        return ok({ items: Array.isArray(json) ? json : json?.results || [] });
      }
    } catch (e: any) { return fail(e.message); }
  });

/* ----------------------------- Threat Feed (URLhaus) ----------------------------- */
export const getThreatFeed = createServerFn({ method: "GET" })
  .handler(async () => {
    try {
      // Call our backend
      try {
        const json = await safeJson(`${BACKEND_URL}/threat-intel/malware/recent`);
        return ok({ items: json });
      } catch (backendError) {
        const json = await safeJson("https://urlhaus-api.abuse.ch/v1/urls/recent/");
        return ok({ items: json?.urls || [] });
      }
    } catch (e: any) { return fail(e.message); }
  });
