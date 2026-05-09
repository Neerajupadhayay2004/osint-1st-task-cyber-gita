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

/* ----------------------------- IP / Domain ----------------------------- */
export const lookupIp = createServerFn({ method: "POST" })
  .inputValidator((d: { query: string }) => d)
  .handler(async ({ data }) => {
    try {
      const q = cleanDomain(data.query);
      if (!q) return fail("Empty query");
      
      // Try to call our backend first
      try {
        const json = await safeJson(`${BACKEND_URL}/osint/ip/${encodeURIComponent(q)}`);
        return ok(json);
      } catch (backendError) {
        console.warn("Backend lookup failed, falling back to direct API:", backendError);
        // ip-api.com — free, no key
        const json = await safeJson(`http://ip-api.com/json/${encodeURIComponent(q)}?fields=66846719`);
        if (json?.status === "fail") return fail(json.message || "Lookup failed");
        return ok(json);
      }
    } catch (e: any) { return fail(e.message); }
  });

/* ----------------------------- Subdomains via crt.sh ----------------------------- */
export const lookupCertificates = createServerFn({ method: "POST" })
  .inputValidator((d: { domain: string }) => d)
  .handler(async ({ data }) => {
    try {
      const domain = cleanDomain(data.domain);
      if (!domain) return fail("Empty domain");
      
      // crt.sh is notoriously slow and often returns 502/504
      // We set a shorter timeout and handle errors gracefully
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s timeout

      try {
        const res = await fetch(`https://crt.sh/?q=${encodeURIComponent("%." + domain)}&output=json`, {
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (res.status === 502 || res.status === 504 || res.status === 503) {
          return fail("crt.sh service is temporarily overloaded. Please try again in a few minutes.");
        }

        if (!res.ok) {
          return fail(`Certificate transparency service returned error ${res.status}`);
        }

        const json = await res.json();
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
      } catch (err: any) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
          return fail("Request to crt.sh timed out. The service is currently slow.");
        }
        throw err;
      }
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
        const json = await safeJson(`${BACKEND_URL}/threat-intel/cves/search?q=${encodeURIComponent(q)}`);
        return ok({ items: json });
      } catch (backendError) {
        // If looks like a CVE id
        if (/^CVE-\d{4}-\d{4,}$/i.test(q)) {
          const json = await safeJson(`https://cve.circl.lu/api/cve/${q.toUpperCase()}`);
          return ok({ items: json ? [json] : [] });
        }
        const json = await safeJson(`https://cve.circl.lu/api/search/${encodeURIComponent(q)}`);
        const items = (json?.results || json?.data || json || []).slice(0, 30);
        return ok({ items });
      }
    } catch (e: any) { return fail(e.message); }
  });

/* ----------------------------- CISA KEV (Known Exploited) ----------------------------- */
export const fetchKev = createServerFn({ method: "GET" })
  .handler(async () => {
    try {
      const json = await safeJson("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
      return ok({
        catalogVersion: json.catalogVersion,
        count: json.count,
        dateReleased: json.dateReleased,
        vulnerabilities: (json.vulnerabilities || []).slice(0, 100),
      });
    } catch (e: any) { return fail(e.message); }
  });

/* ----------------------------- Threat Feed (CIRCL last CVEs) ----------------------------- */
export const fetchThreatFeed = createServerFn({ method: "GET" })
  .handler(async () => {
    try {
      // Call our backend
      try {
        const json = await safeJson(`${BACKEND_URL}/threat-intel/cves`);
        return ok({ items: json });
      } catch (backendError) {
        const json = await safeJson("https://cve.circl.lu/api/last");
        return ok({ items: (json || []).slice(0, 25) });
      }
    } catch (e: any) { return fail(e.message); }
  });

/* ----------------------------- DNS over HTTPS (Cloudflare) ----------------------------- */
export const dnsLookup = createServerFn({ method: "POST" })
  .inputValidator((d: { domain: string; type?: string }) => d)
  .handler(async ({ data }) => {
    try {
      const domain = cleanDomain(data.domain);
      const type = data.type || "A";
      if (!domain) return fail("Empty domain");
      const types = type === "ALL" ? ["A", "AAAA", "MX", "TXT", "NS", "CNAME"] : [type];
      const results: Record<string, any[]> = {};
      await Promise.all(types.map(async (t) => {
        const json = await safeJson(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${t}`,
          { headers: { accept: "application/dns-json" } }).catch(() => null);
        results[t] = json?.Answer || [];
      }));
      return ok(results);
    } catch (e: any) { return fail(e.message); }
  });

/* ----------------------------- WHOIS-ish via RDAP ----------------------------- */
export const rdapLookup = createServerFn({ method: "POST" })
  .inputValidator((d: { domain: string }) => d)
  .handler(async ({ data }) => {
    try {
      const domain = cleanDomain(data.domain);
      if (!domain) return fail("Empty domain");
      const json = await safeJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
      return ok(json);
    } catch (e: any) { return fail(e.message); }
  });

/* ============================ PAID / KEY-BASED OSINT ============================ */

/* ----------------------------- Shodan host lookup ----------------------------- */
export const shodanHost = createServerFn({ method: "POST" })
  .inputValidator((d: { ip: string }) => d)
  .handler(async ({ data }) => {
    try {
      const ip = data.ip.trim();
      if (!ip) return fail("Empty IP");

      // Call our backend
      try {
        const json = await safeJson(`${BACKEND_URL}/shodan/${encodeURIComponent(ip)}`);
        return ok(json);
      } catch (backendError) {
        const key = process.env.SHODAN_API_KEY;
        if (!key) return fail("SHODAN_API_KEY not configured");
        const json = await safeJson(`https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${key}`);
        return ok(json);
      }
    } catch (e: any) { return fail(e.message); }
  });

/* ----------------------------- Shodan search ----------------------------- */
export const shodanSearch = createServerFn({ method: "POST" })
  .inputValidator((d: { query: string }) => d)
  .handler(async ({ data }) => {
    try {
      const key = process.env.SHODAN_API_KEY;
      if (!key) return fail("SHODAN_API_KEY not configured");
      const q = data.query.trim();
      if (!q) return fail("Empty query");
      const json = await safeJson(`https://api.shodan.io/shodan/host/count?key=${key}&query=${encodeURIComponent(q)}&facets=country,org,port`);
      return ok(json);
    } catch (e: any) { return fail(e.message); }
  });

/* ----------------------------- AbuseIPDB ----------------------------- */
export const abuseCheck = createServerFn({ method: "POST" })
  .inputValidator((d: { ip: string }) => d)
  .handler(async ({ data }) => {
    try {
      const ip = data.ip.trim();
      if (!ip) return fail("Empty IP");

      // Call our backend
      try {
        const json = await safeJson(`${BACKEND_URL}/abuseipdb/${encodeURIComponent(ip)}`);
        return ok(json);
      } catch (backendError) {
        const key = process.env.ABUSEIPDB_API_KEY;
        if (!key) return fail("ABUSEIPDB_API_KEY not configured");
        const json = await safeJson(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=true`,
          { headers: { Key: key, Accept: "application/json" } }
        );
        return ok(json?.data || json);
      }
    } catch (e: any) { return fail(e.message); }
  });


/* ----------------------------- VirusTotal ----------------------------- */
export const vtLookup = createServerFn({ method: "POST" })
  .inputValidator((d: { kind: "ip" | "domain" | "hash" | "url"; value: string }) => d)
  .handler(async ({ data }) => {
    try {
      const v = data.value.trim();
      if (!v) return fail("Empty value");

      // Call our backend
      try {
        const json = await safeJson(`${BACKEND_URL}/virustotal/${data.kind}/${encodeURIComponent(v)}`);
        return ok(json);
      } catch (backendError) {
        const key = process.env.VIRUSTOTAL_API_KEY;
        if (!key) return fail("VIRUSTOTAL_API_KEY not configured");
        
        let kind = data.kind;

        // Auto-correction logic: If user selected 'ip' but it looks like a domain, fix it.
        const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(v) || v.includes(":");
        const isHash = /^[a-f0-9]{32,64}$/i.test(v);
        const isUrl = v.startsWith("http://") || v.startsWith("https://");

        if (kind === "ip" && !isIp && !isHash && !isUrl) kind = "domain";
        else if (kind === "domain" && isIp) kind = "ip";

        let path = "";
        if (kind === "ip") path = `ip_addresses/${encodeURIComponent(v)}`;
        else if (kind === "domain") path = `domains/${encodeURIComponent(v)}`;
        else if (kind === "hash") path = `files/${encodeURIComponent(v)}`;
        else if (kind === "url") {
          const id = btoa(v).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
          path = `urls/${id}`;
        }

        const json = await safeJson(`https://www.virustotal.com/api/v3/${path}`, {
          headers: { "x-apikey": key, Accept: "application/json" },
        });
        
        return ok({ ...json?.data || json, _detected_kind: kind });
      }
    } catch (e: any) { 
      return fail(e.message); 
    }
  });



