import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import AppShell from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { ResultCard, KV } from "@/components/ResultCard";
import { vtLookup, abuseCheck } from "@/lib/osint.functions";
import { ScanSearch, Search, ShieldAlert } from "lucide-react";
import { AiAnalysis } from "@/components/AiAnalysis";

export const Route = createFileRoute("/virustotal")({
  component: Page,
  head: () => ({ meta: [{ title: "VirusTotal & AbuseIPDB — CyberGita OSINT" }] }),
});

type Kind = "ip" | "domain" | "hash" | "url";

function Page() {
  const vtFn = useServerFn(vtLookup);
  const abuseFn = useServerFn(abuseCheck);
  const [kind, setKind] = useState<Kind>("domain");
  const [value, setValue] = useState("google.com");
  const [vt, setVt] = useState<any>(null);
  const [abuse, setAbuse] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  const run = async (e?: React.FormEvent) => {
    e?.preventDefault(); setBusy(true); setVt(null); setAbuse(null);
    try {
      const v = await vtFn({ data: { kind, value } });
      setVt(v);
      if (kind === "ip") {
        const a = await abuseFn({ data: { ip: value } });
        setAbuse(a);
      }
    } finally { setBusy(false); }
  };

  const stats = vt?.ok ? (vt.data.attributes?.last_analysis_stats || {}) : {};
  const total = Object.values(stats).reduce((a: number, b: any) => a + (b || 0), 0);
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;

  return (
    <AppShell>
      <PageHeader icon={<ScanSearch className="size-5" />} title="VirusTotal + AbuseIPDB"
        description="Multi-engine reputation analysis for IPs, domains, file hashes and URLs. IPs cross-checked against AbuseIPDB." />

      <form onSubmit={run} className="glass-card p-4 mb-6 flex flex-col sm:flex-row gap-2">
        <select value={kind} onChange={e => setKind(e.target.value as Kind)}
          className="bg-input border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-ring">
          <option value="domain">Domain</option>
          <option value="ip">IP address</option>
          <option value="url">URL</option>
          <option value="hash">File hash (SHA-256)</option>
        </select>
        <input value={value} onChange={e => setValue(e.target.value)} placeholder="enter target…"
          className="flex-1 bg-input border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring" />
        <button disabled={busy} className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-md bg-primary text-primary-foreground font-medium hover:opacity-90 disabled:opacity-50">
          <Search className="size-4" /> {busy ? "Scanning…" : "Scan"}
        </button>
      </form>

      {vt && !vt.ok && <div className="glass-card p-4 text-destructive text-sm mb-4">{vt.error}</div>}

      {vt?.ok && (
        <div className="grid lg:grid-cols-3 gap-4 mb-4">
          <div className="glass-card p-5">
            <div className="text-xs uppercase tracking-wider text-muted-foreground">Detection</div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className={`text-3xl font-mono font-semibold ${malicious > 0 ? "text-destructive" : "text-success"}`}>{malicious}</span>
              <span className="text-muted-foreground text-sm">/ {total} engines</span>
            </div>
            <div className="text-xs text-muted-foreground mt-1">Suspicious: {suspicious} · Harmless: {stats.harmless || 0} · Undetected: {stats.undetected || 0}</div>
          </div>
          <div className="glass-card p-5 lg:col-span-2">
            <div className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Reputation</div>
            <KV k="Reputation score" v={vt.data.attributes?.reputation ?? "—"} />
            <KV k="Type" v={vt.data.type} />
            <KV k="Last analysis" v={vt.data.attributes?.last_analysis_date ? new Date(vt.data.attributes.last_analysis_date * 1000).toLocaleString() : "—"} />
            <KV k="Categories" v={Object.values(vt.data.attributes?.categories || {}).join(", ") || "—"} />
            <KV k="Total votes" v={`👍 ${vt.data.attributes?.total_votes?.harmless || 0} · 👎 ${vt.data.attributes?.total_votes?.malicious || 0}`} />
          </div>
        </div>
      )}

      {vt?.ok && (
        <ResultCard title="Engine results" subtitle={`${Object.keys(vt.data.attributes?.last_analysis_results || {}).length} engines`}>
          <div className="max-h-[420px] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-card text-xs uppercase tracking-wider text-muted-foreground">
                <tr><th className="text-left py-2">Engine</th><th className="text-left py-2">Category</th><th className="text-left py-2">Result</th></tr>
              </thead>
              <tbody>
                {Object.entries(vt.data.attributes?.last_analysis_results || {}).map(([engine, r]: [string, any]) => (
                  <tr key={engine} className="border-t border-border/60">
                    <td className="py-1.5 font-mono">{engine}</td>
                    <td className={`py-1.5 ${r.category === "malicious" ? "text-destructive" : r.category === "suspicious" ? "text-warning" : "text-muted-foreground"}`}>{r.category}</td>
                    <td className="py-1.5 font-mono text-xs">{r.result || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </ResultCard>
      )}

      {abuse?.ok && (
        <div className="mt-4">
          <ResultCard title={<span className="flex items-center gap-2"><ShieldAlert className="size-4 text-warning"/> AbuseIPDB</span>} subtitle={`${abuse.data.ipAddress}`}>
            <div className="grid sm:grid-cols-2 gap-x-6">
              <KV k="Abuse confidence" v={`${abuse.data.abuseConfidenceScore}%`} />
              <KV k="Total reports" v={abuse.data.totalReports} />
              <KV k="Distinct users" v={abuse.data.numDistinctUsers} />
              <KV k="Country" v={abuse.data.countryCode} />
              <KV k="ISP" v={abuse.data.isp} />
              <KV k="Domain" v={abuse.data.domain} />
              <KV k="Usage type" v={abuse.data.usageType} />
              <KV k="Last reported" v={abuse.data.lastReportedAt} />
            </div>
          </ResultCard>
        </div>
      )}
      {abuse && !abuse.ok && <div className="glass-card p-4 text-destructive text-sm mt-4">AbuseIPDB: {abuse.error}</div>}

      {vt?.ok && (
        <div className="mt-6">
          <AiAnalysis context={`VirusTotal ${kind}`} data={{
            target: value, kind,
            stats, reputation: vt.data.attributes?.reputation,
            categories: vt.data.attributes?.categories,
            abuse: abuse?.ok ? { score: abuse.data.abuseConfidenceScore, reports: abuse.data.totalReports, usage: abuse.data.usageType } : null,
          }} />
        </div>
      )}
    </AppShell>
  );
}
