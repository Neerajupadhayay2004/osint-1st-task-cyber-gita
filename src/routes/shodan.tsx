import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import AppShell from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { ResultCard, KV } from "@/components/ResultCard";
import { shodanHost, shodanSearch } from "@/lib/osint.functions";
import { Server, Search, Download } from "lucide-react";
import { downloadCsv, downloadPdf } from "@/lib/export";

export const Route = createFileRoute("/shodan")({
  component: Page,
  head: () => ({ meta: [{ title: "Shodan Recon — CyberGita OSINT" }] }),
});

function Page() {
  const hostFn = useServerFn(shodanHost);
  const searchFn = useServerFn(shodanSearch);
  const [ip, setIp] = useState("8.8.8.8");
  const [q, setQ] = useState("apache country:US");
  const [hostRes, setHostRes] = useState<any>(null);
  const [searchRes, setSearchRes] = useState<any>(null);
  const [busy, setBusy] = useState(false);

  const runHost = async (e?: React.FormEvent) => {
    e?.preventDefault(); setBusy(true); setHostRes(null);
    try { setHostRes(await hostFn({ data: { ip } })); } finally { setBusy(false); }
  };
  const runSearch = async (e?: React.FormEvent) => {
    e?.preventDefault(); setBusy(true); setSearchRes(null);
    try { setSearchRes(await searchFn({ data: { query: q } })); } finally { setBusy(false); }
  };

  const exportHostCsv = () => {
    if (!hostRes?.ok) return;
    const d = hostRes.data;
    const rows = (d.data || []).map((s: any) => [s.port, s.transport, s.product, s.version, (s.hostnames || []).join(";"), (s.cpe || []).join(";")]);
    downloadCsv(`shodan-${d.ip_str || ip}.csv`, ["port","proto","product","version","hostnames","cpe"], rows);
  };

  return (
    <AppShell>
      <PageHeader icon={<Server className="size-5" />} title="Shodan Recon"
        description="Internet-exposed host intelligence, open ports, banners and exploit context via Shodan." />

      <div className="grid lg:grid-cols-2 gap-4 mb-4">
        <form onSubmit={runHost} className="glass-card p-4">
          <div className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Host lookup</div>
          <div className="flex gap-2">
            <input value={ip} onChange={e => setIp(e.target.value)} placeholder="IP address"
              className="flex-1 bg-input border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring" />
            <button disabled={busy} className="px-3 py-2 rounded-md bg-primary text-primary-foreground font-medium hover:opacity-90 disabled:opacity-50 inline-flex items-center gap-2">
              <Search className="size-4" /> Lookup
            </button>
          </div>
        </form>

        <form onSubmit={runSearch} className="glass-card p-4">
          <div className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Facet search</div>
          <div className="flex gap-2">
            <input value={q} onChange={e => setQ(e.target.value)} placeholder='e.g. apache country:US'
              className="flex-1 bg-input border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring" />
            <button disabled={busy} className="px-3 py-2 rounded-md border border-border hover:bg-secondary inline-flex items-center gap-2">
              <Search className="size-4" /> Count
            </button>
          </div>
        </form>
      </div>

      {hostRes && !hostRes.ok && <div className="glass-card p-4 text-destructive text-sm mb-4">{hostRes.error}</div>}
      {hostRes?.ok && (
        <div className="grid lg:grid-cols-2 gap-4 mb-4">
          <ResultCard title={`Host ${hostRes.data.ip_str}`} subtitle={hostRes.data.org}
            footer={<button onClick={exportHostCsv} className="inline-flex items-center gap-2 hover:text-foreground"><Download className="size-3.5"/> Export ports CSV</button>}>
            <KV k="Country" v={`${hostRes.data.country_name || ""} (${hostRes.data.country_code || ""})`} />
            <KV k="City" v={hostRes.data.city} />
            <KV k="ISP" v={hostRes.data.isp} />
            <KV k="ASN" v={hostRes.data.asn} />
            <KV k="OS" v={hostRes.data.os} />
            <KV k="Open Ports" v={(hostRes.data.ports || []).join(", ")} />
            <KV k="Hostnames" v={(hostRes.data.hostnames || []).join(", ")} />
            <KV k="Vulns" v={Object.keys(hostRes.data.vulns || {}).join(", ") || "None reported"} />
          </ResultCard>
          <ResultCard title="Service banners" subtitle={`${(hostRes.data.data || []).length} services`}>
            <div className="max-h-96 overflow-y-auto space-y-2 text-xs font-mono">
              {(hostRes.data.data || []).slice(0, 30).map((s: any, i: number) => (
                <div key={i} className="p-2 rounded border border-border/60 bg-secondary/20">
                  <div className="text-primary">{s.port}/{s.transport} · {s.product || "?"} {s.version || ""}</div>
                  <div className="text-muted-foreground line-clamp-2 mt-1">{(s.data || "").slice(0, 200)}</div>
                </div>
              ))}
            </div>
          </ResultCard>
        </div>
      )}

      {searchRes && !searchRes.ok && <div className="glass-card p-4 text-destructive text-sm">{searchRes.error}</div>}
      {searchRes?.ok && (
        <ResultCard title="Search results" subtitle={`${searchRes.data.total?.toLocaleString?.() || 0} matches`}>
          <div className="grid sm:grid-cols-3 gap-4">
            {["country", "org", "port"].map((f) => (
              <div key={f}>
                <div className="text-xs uppercase tracking-wider text-muted-foreground mb-2">{f}</div>
                <ul className="space-y-1 text-sm">
                  {(searchRes.data.facets?.[f] || []).slice(0, 10).map((row: any) => (
                    <li key={row.value} className="flex justify-between font-mono">
                      <span>{row.value}</span><span className="text-primary">{row.count.toLocaleString()}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </ResultCard>
      )}
    </AppShell>
  );
}
