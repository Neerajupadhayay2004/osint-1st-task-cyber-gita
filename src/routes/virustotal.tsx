import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import AppShell from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { ResultCard, KV } from "@/components/ResultCard";
import { vtLookup, abuseCheck, dnsLookup } from "@/lib/osint.functions";
import { ScanSearch, Search, ShieldAlert, Globe, Hash, Link as LinkIcon, Network } from "lucide-react";

export const Route = createFileRoute("/virustotal")({
  component: Page,
  head: () => ({ meta: [{ title: "VirusTotal & AbuseIPDB — CyberGita OSINT" }] }),
});

type Kind = "ip" | "domain" | "hash" | "url";

function Page() {
  const vtFn = useServerFn(vtLookup);
  const abuseFn = useServerFn(abuseCheck);
  const dnsFn = useServerFn(dnsLookup);
  const [kind, setKind] = useState<Kind>("domain");
  const [value, setValue] = useState("google.com");
  const [vt, setVt] = useState<any>(null);
  const [abuse, setAbuse] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [resolvedIp, setResolvedIp] = useState<string | null>(null);

  const run = async (e?: React.FormEvent) => {
    e?.preventDefault(); 
    const val = value.trim();
    if (!val) return;

    setBusy(true); 
    setVt(null); 
    setAbuse(null);
    setResolvedIp(null);

    try {
      // 1. VirusTotal Lookup (with auto-detection in server function)
      const v = await vtFn({ data: { kind, value: val } });
      setVt(v);

      // 2. AbuseIPDB Cross-check logic
      let ipToCheck = "";
      const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(val) || val.includes(":");
      
      if (isIp) {
        ipToCheck = val;
      } else if (kind === "domain" || (!isIp && !val.includes("/") && val.includes("."))) {
        // Try to resolve domain to IP for AbuseIPDB
        const dns = await dnsFn({ data: { domain: val, type: "A" } });
        if (dns.ok && dns.data.A && dns.data.A.length > 0) {
          ipToCheck = dns.data.A[0].data;
          setResolvedIp(ipToCheck);
        }
      }

      if (ipToCheck) {
        const a = await abuseFn({ data: { ip: ipToCheck } });
        setAbuse(a);
      }
    } catch (err) {
      console.error("Scan failed:", err);
    } finally { 
      setBusy(false); 
    }
  };

  const stats = vt?.ok ? (vt.data.attributes?.last_analysis_stats || {}) : {};
  const total = Object.values(stats).reduce((a: number, b: any) => a + (b || 0), 0);
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const detectedKind = vt?.ok ? vt.data._detected_kind : kind;

  const getIcon = () => {
    switch (detectedKind) {
      case "ip": return <Network className="size-4" />;
      case "domain": return <Globe className="size-4" />;
      case "hash": return <Hash className="size-4" />;
      case "url": return <LinkIcon className="size-4" />;
      default: return <ScanSearch className="size-4" />;
    }
  };

  return (
    <AppShell>
      <PageHeader 
        icon={<ScanSearch className="size-5" />} 
        title="VirusTotal + AbuseIPDB"
        description="Multi-engine reputation analysis for IPs, domains, file hashes and URLs. IPs cross-checked against AbuseIPDB." 
      />

      <form onSubmit={run} className="glass-card p-4 mb-6 flex flex-col sm:flex-row gap-2">
        <select value={kind} onChange={e => setKind(e.target.value as Kind)}
          className="bg-input border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring">
          <option value="domain">Domain</option>
          <option value="ip">IP address</option>
          <option value="url">URL</option>
          <option value="hash">File hash</option>
        </select>
        <input 
          value={value} 
          onChange={e => setValue(e.target.value)} 
          placeholder="Enter IP, Domain, Hash or URL..."
          className="flex-1 bg-input border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring" 
        />
        <button disabled={busy} className="inline-flex items-center justify-center gap-2 px-6 py-2 rounded-md bg-primary text-primary-foreground font-medium hover:opacity-90 transition-all disabled:opacity-50">
          <Search className="size-4" /> {busy ? "Scanning..." : "Analyze"}
        </button>
      </form>

      {vt && !vt.ok && (
        <div className="glass-card p-4 border-l-4 border-destructive bg-destructive/10 text-destructive text-sm mb-6">
          <p className="font-bold mb-1">VirusTotal Error</p>
          {vt.error}
        </div>
      )}

      {vt?.ok && (
        <div className="animate-in fade-in slide-in-from-bottom-2 duration-500">
          <div className="flex items-center gap-2 mb-4 text-sm font-medium text-muted-foreground bg-secondary/50 w-fit px-3 py-1 rounded-full border border-border">
            {getIcon()}
            <span className="uppercase tracking-wider">{detectedKind}</span>
            <span className="opacity-40">|</span>
            <span className="font-mono">{value}</span>
          </div>

          <div className="grid lg:grid-cols-3 gap-4 mb-6">
            <div className="glass-card p-6 flex flex-col justify-center">
              <div className="text-xs uppercase tracking-wider text-muted-foreground font-bold mb-1">Security Vendors</div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className={`text-4xl font-mono font-bold ${malicious > 0 ? "text-destructive" : "text-success"}`}>
                  {malicious}
                </span>
                <span className="text-muted-foreground text-lg">/ {total}</span>
              </div>
              <div className="text-xs text-muted-foreground mt-3 flex gap-3">
                <span className={suspicious > 0 ? "text-warning" : ""}>Suspicious: {suspicious}</span>
                <span>Harmless: {stats.harmless || 0}</span>
              </div>
            </div>

            <div className="glass-card p-6 lg:col-span-2">
              <div className="text-xs uppercase tracking-wider text-muted-foreground font-bold mb-4">Resource Details</div>
              <div className="grid sm:grid-cols-2 gap-y-3 gap-x-8">
                <KV k="Reputation Score" v={<span className={`font-bold ${vt.data.attributes?.reputation > 0 ? "text-success" : vt.data.attributes?.reputation < 0 ? "text-destructive" : ""}`}>{vt.data.attributes?.reputation ?? 0}</span>} />
                <KV k="Resource Type" v={vt.data.type} />
                <KV k="Last Analysis" v={vt.data.attributes?.last_analysis_date ? new Date(vt.data.attributes.last_analysis_date * 1000).toLocaleString() : "—"} />
                <KV k="Provider Votes" v={`👍 ${vt.data.attributes?.total_votes?.harmless || 0} · 👎 ${vt.data.attributes?.total_votes?.malicious || 0}`} />
              </div>
              {vt.data.attributes?.categories && (
                <div className="mt-4 pt-4 border-t border-border/40">
                  <div className="text-[10px] uppercase text-muted-foreground mb-1">Categories</div>
                  <div className="flex flex-wrap gap-1">
                    {Object.values(vt.data.attributes.categories).map((c: any, i) => (
                      <span key={i} className="text-[10px] bg-secondary px-2 py-0.5 rounded border border-border/50">{c}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="grid lg:grid-cols-2 gap-6">
            <ResultCard 
              title="Engine Analysis" 
              subtitle={`${Object.keys(vt.data.attributes?.last_analysis_results || {}).length} security vendors analyzed this resource`}
            >
              <div className="max-h-[500px] overflow-y-auto pr-2 custom-scrollbar">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-card/95 backdrop-blur-sm text-[10px] uppercase tracking-widest text-muted-foreground z-10">
                    <tr>
                      <th className="text-left py-3 font-bold">Security Vendor</th>
                      <th className="text-left py-3 font-bold">Category</th>
                      <th className="text-left py-3 font-bold">Result</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/40">
                    {Object.entries(vt.data.attributes?.last_analysis_results || {}).map(([engine, r]: [string, any]) => (
                      <tr key={engine} className="hover:bg-secondary/30 transition-colors">
                        <td className="py-2.5 font-medium">{engine}</td>
                        <td className="py-2.5">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${
                            r.category === "malicious" ? "bg-destructive/20 text-destructive" : 
                            r.category === "suspicious" ? "bg-warning/20 text-warning" : 
                            r.category === "harmless" ? "bg-success/20 text-success" :
                            "bg-muted text-muted-foreground"
                          }`}>
                            {r.category}
                          </span>
                        </td>
                        <td className="py-2.5 font-mono text-[11px] text-muted-foreground italic">{r.result || "clean"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </ResultCard>

            <div className="flex flex-col gap-6">
              {abuse?.ok ? (
                <ResultCard 
                  title={<span className="flex items-center gap-2"><ShieldAlert className="size-4 text-warning"/> AbuseIPDB Intelligence</span>} 
                  subtitle={resolvedIp ? `Resolved IP: ${resolvedIp}` : `IP: ${abuse.data.ipAddress}`}
                >
                  <div className="grid sm:grid-cols-2 gap-y-4 gap-x-6">
                    <div className="p-3 rounded-lg bg-secondary/30 border border-border/50">
                      <div className="text-[10px] uppercase text-muted-foreground mb-1">Abuse Confidence</div>
                      <div className={`text-2xl font-mono font-bold ${abuse.data.abuseConfidenceScore > 50 ? "text-destructive" : abuse.data.abuseConfidenceScore > 20 ? "text-warning" : "text-success"}`}>
                        {abuse.data.abuseConfidenceScore}%
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-secondary/30 border border-border/50">
                      <div className="text-[10px] uppercase text-muted-foreground mb-1">Total Reports</div>
                      <div className="text-2xl font-mono font-bold">{abuse.data.totalReports}</div>
                    </div>
                    <KV k="ISP" v={abuse.data.isp} />
                    <KV k="Usage Type" v={abuse.data.usageType} />
                    <KV k="Country" v={`${abuse.data.countryCode} ${abuse.data.countryName || ""}`} />
                    <KV k="Domain" v={abuse.data.domain || "—"} />
                    <KV k="Last Reported" v={abuse.data.lastReportedAt ? new Date(abuse.data.lastReportedAt).toLocaleString() : "Never"} />
                    <KV k="Whitelist Status" v={abuse.data.isWhitelisted ? "✅ Whitelisted" : "❌ Not Whitelisted"} />
                  </div>
                </ResultCard>
              ) : abuse && (
                <div className="glass-card p-4 border-l-4 border-warning bg-warning/5 text-warning-foreground text-sm">
                  <p className="font-bold flex items-center gap-2 mb-1"><ShieldAlert className="size-4"/> AbuseIPDB Notice</p>
                  {abuse.error || "No IP intelligence found for this resource."}
                </div>
              )}

              {vt?.ok && vt.data.attributes?.last_http_response_content_length && (
                <ResultCard title="HTTP Metadata">
                  <div className="space-y-2">
                    <KV k="Status Code" v={vt.data.attributes?.last_http_response_code} />
                    <KV k="Content Length" v={`${vt.data.attributes?.last_http_response_content_length} bytes`} />
                    <KV k="Server" v={vt.data.attributes?.last_http_response_headers?.Server || "—"} />
                  </div>
                </ResultCard>
              )}
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}

