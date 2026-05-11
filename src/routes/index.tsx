import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useQuery } from "@tanstack/react-query";
import { useState, useEffect } from "react";
import AppShell from "@/components/AppShell";
import { fetchThreatFeed, fetchKev } from "@/lib/osint.functions";
import { Activity, ShieldAlert, Bug, Globe, Mail, Radio, ArrowRight, Database, AlertTriangle, FileDown, FileText, Server, ScanSearch, BellRing } from "lucide-react";
import { downloadCsv, downloadPdf } from "@/lib/export";
import { toast } from "sonner";

export const Route = createFileRoute("/")({
  component: Dashboard,
  head: () => ({ meta: [
    { title: "CyberGita OSINT — Threat Intelligence Platform" },
    { name: "description", content: "Open-source intelligence dashboard: threat feeds, breach lookups, CVE search, IP/domain reconnaissance and more." },
  ]}),
});

function Dashboard() {
  const feedFn = useServerFn(fetchThreatFeed);
  const kevFn = useServerFn(fetchKev);
  
  // Custom analytics fetch
  const [statsData, setStatsData] = useState<any>(null);
  
  useEffect(() => {
    fetch("http://localhost:8000/api/analytics/summary")
      .then(res => res.json())
      .then(data => setStatsData(data))
      .catch(err => console.warn("Analytics backend not available:", err));
  }, []);

  const feed = useQuery({ queryKey: ["feed"], queryFn: () => feedFn(), staleTime: 60_000 });
  const kev = useQuery({ queryKey: ["kev"], queryFn: () => kevFn(), staleTime: 300_000 });

  const recentCves = feed.data?.ok ? feed.data.data.items.slice(0, 6) : [];
  const kevList = kev.data?.ok ? kev.data.data.vulnerabilities.slice(0, 6) : [];
  const kevCount = kev.data?.ok ? kev.data.data.count : null;

  const stats = [
    { label: "Live CVEs (24h)", value: feed.data?.ok ? feed.data.data.items.length : "—", icon: Bug, tone: "text-primary" },
    { label: "High Threats", value: statsData?.high_threats ?? "—", icon: ShieldAlert, tone: "text-destructive" },
    { label: "Total Scans", value: statsData?.total_scans ?? "—", icon: Database, tone: "text-accent" },
    { label: "System Status", value: statsData?.system_status ?? "Operational", icon: Activity, tone: "text-success" },
  ];


  const tools = [
    { to: "/threat-feed", icon: Radio, title: "Threat Feed", desc: "Latest CVEs as they're published" },
    { to: "/alerts", icon: BellRing, title: "Real-time Alerts", desc: "Live notifications for new threats" },
    { to: "/ip-domain", icon: Globe, title: "IP / Domain Lookup", desc: "Geolocation, ASN, hosting" },
    { to: "/email-breach", icon: Mail, title: "Email Breach Checker", desc: "Search public breach corpora" },
    { to: "/cve-search", icon: Bug, title: "CVE Search", desc: "Query CIRCL CVE database" },
    { to: "/kev", icon: ShieldAlert, title: "CISA KEV Catalog", desc: "Known exploited vulnerabilities" },
    { to: "/dns-recon", icon: Globe, title: "DNS / Subdomains", desc: "DoH + crt.sh recon" },
    { to: "/shodan", icon: Server, title: "Shodan Recon", desc: "Exposed hosts & banners (paid)" },
    { to: "/virustotal", icon: ScanSearch, title: "VirusTotal + AbuseIPDB", desc: "Reputation & multi-engine scan" },
  ];

  const exportCsv = () => {
    if (!feed.data?.ok && !kev.data?.ok) { toast.error("Wait for data to load"); return; }
    const cveRows = recentCves.map((c: any) => [c.id || c.cveMetadata?.cveId, (c.summary || c.containers?.cna?.descriptions?.[0]?.value || "").slice(0, 200)]);
    const kevRows = kevList.map((v: any) => [v.cveID, v.vendorProject, v.product, v.dateAdded]);
    downloadCsv("dashboard-report.csv",
      ["section","col1","col2","col3","col4"],
      [
        ...cveRows.map((r: any[]) => ["latest_cve", ...r, "", ""]),
        ...kevRows.map((r: any[]) => ["kev", ...r]),
      ]);
    toast.success("CSV downloaded");
  };

  const exportPdf = () => {
    if (!feed.data?.ok && !kev.data?.ok) { toast.error("Wait for data to load"); return; }
    downloadPdf({
      filename: `cybergita-dashboard-${new Date().toISOString().slice(0,10)}.pdf`,
      title: "Threat Intelligence Dashboard Snapshot",
      subtitle: `Live CVEs: ${feed.data?.ok ? feed.data.data.items.length : "—"}  ·  CISA KEV catalog: ${kevCount ?? "—"} entries`,
      sections: [
        { heading: "Latest published CVEs", headers: ["CVE", "Summary"],
          rows: recentCves.map((c: any) => [c.id || c.cveMetadata?.cveId, (c.summary || c.containers?.cna?.descriptions?.[0]?.value || "").slice(0, 220)]) },
        { heading: "Known Exploited Vulnerabilities (CISA KEV)", headers: ["CVE", "Vendor", "Product", "Vulnerability", "Added"],
          rows: kevList.map((v: any) => [v.cveID, v.vendorProject, v.product, v.vulnerabilityName, v.dateAdded]) },
      ],
    });
    toast.success("PDF report generated");
  };


  return (
    <AppShell>
      {/* Hero */}
      <section className="relative overflow-hidden glass-card p-6 md:p-10 mb-8">
        <div className="absolute inset-0 grid-bg opacity-40 pointer-events-none" />
        <div className="relative max-w-3xl">
          <div className="inline-flex items-center gap-2 text-xs font-mono px-2.5 py-1 rounded-full border border-primary/30 bg-primary/5 text-primary mb-4">
            <span className="pulse-dot" /> live · open source intel
          </div>
          <h1 className="text-3xl md:text-5xl font-semibold tracking-tight">
            <span className="text-gradient">Threat intelligence,</span><br/> from the open web.
          </h1>
          <p className="mt-4 text-muted-foreground max-w-xl">
            A unified OSINT workspace for analysts. Track breaches, monitor CVEs and known exploited vulnerabilities,
            and reconnoiter domains — all from free, public sources.
          </p>
          <div className="mt-6 flex gap-2 sm:gap-3 flex-wrap">
            <Link to="/threat-feed" className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-primary text-primary-foreground font-medium hover:opacity-90 transition text-sm">
              View live feed <ArrowRight className="size-4" />
            </Link>
            <Link to="/alerts" className="inline-flex items-center gap-2 px-4 py-2 rounded-md border border-border hover:bg-secondary transition text-sm">
              <BellRing className="size-4" /> Real-time alerts
            </Link>
            <button onClick={exportCsv} className="inline-flex items-center gap-2 px-4 py-2 rounded-md border border-border hover:bg-secondary transition text-sm">
              <FileDown className="size-4" /> Export CSV
            </button>
            <button onClick={exportPdf} className="inline-flex items-center gap-2 px-4 py-2 rounded-md border border-border hover:bg-secondary transition text-sm">
              <FileText className="size-4" /> Export PDF report
            </button>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        {stats.map(s => (
          <div key={s.label} className="glass-card p-5">
            <div className="flex items-center justify-between mb-3">
              <span className="text-xs uppercase tracking-wider text-muted-foreground">{s.label}</span>
              <s.icon className={`size-4 ${s.tone}`} />
            </div>
            <div className="text-2xl font-semibold font-mono">{s.value}</div>
          </div>
        ))}
      </section>

      {/* Tools grid */}
      <section className="mb-8">
        <h2 className="text-lg font-semibold mb-4">Modules</h2>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {tools.map(t => (
            <Link key={t.to} to={t.to} className="glass-card p-5 group hover:border-primary/40 transition">
              <div className="flex items-start justify-between">
                <div className="size-9 rounded-md grid place-items-center bg-primary/10 border border-primary/30 text-primary">
                  <t.icon className="size-4" />
                </div>
                <ArrowRight className="size-4 text-muted-foreground group-hover:text-primary group-hover:translate-x-0.5 transition" />
              </div>
              <div className="mt-4 font-medium">{t.title}</div>
              <div className="text-sm text-muted-foreground mt-1">{t.desc}</div>
            </Link>
          ))}
        </div>
      </section>

      {/* Live preview */}
      <section className="grid lg:grid-cols-2 gap-4">
        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-medium flex items-center gap-2"><Radio className="size-4 text-primary" /> Latest CVEs</h3>
              <p className="text-xs text-muted-foreground font-mono">via cve.circl.lu</p>
            </div>
            <Link to="/threat-feed" className="text-xs text-primary hover:underline">All →</Link>
          </div>
          <ul className="space-y-2">
            {feed.isLoading && <li className="text-sm text-muted-foreground">Loading…</li>}
            {recentCves.map((c: any) => (
              <li key={c.id || c.cveMetadata?.cveId} className="text-sm py-2 border-b border-border/60 last:border-0">
                <div className="font-mono text-primary">{c.id || c.cveMetadata?.cveId}</div>
                <div className="text-muted-foreground line-clamp-2">
                  {c.summary || c.containers?.cna?.descriptions?.[0]?.value || "No description"}
                </div>
              </li>
            ))}
          </ul>
        </div>

        <div className="glass-card p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-medium flex items-center gap-2"><AlertTriangle className="size-4 text-destructive" /> Known Exploited</h3>
              <p className="text-xs text-muted-foreground font-mono">CISA KEV catalog</p>
            </div>
            <Link to="/kev" className="text-xs text-primary hover:underline">All →</Link>
          </div>
          <ul className="space-y-2">
            {kev.isLoading && <li className="text-sm text-muted-foreground">Loading…</li>}
            {kevList.map((v: any) => (
              <li key={v.cveID} className="text-sm py-2 border-b border-border/60 last:border-0">
                <div className="flex justify-between gap-2">
                  <span className="font-mono text-destructive">{v.cveID}</span>
                  <span className="text-xs text-muted-foreground">{v.dateAdded}</span>
                </div>
                <div className="text-muted-foreground line-clamp-1">{v.vendorProject} · {v.product}</div>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </AppShell>
  );
}
