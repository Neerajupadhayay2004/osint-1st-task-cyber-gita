import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import AppShell from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { fetchThreatFeed, fetchKev } from "@/lib/osint.functions";
import { Bell, BellRing, Pause, Play, Trash2 } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/alerts")({
  component: Page,
  head: () => ({ meta: [{ title: "Real-time Threat Alerts — CyberGita OSINT" }] }),
});

type AlertEvt = { id: string; kind: "cve" | "kev"; title: string; summary: string; ts: number };

function Page() {
  const feedFn = useServerFn(fetchThreatFeed);
  const kevFn = useServerFn(fetchKev);
  const [live, setLive] = useState(true);
  const [alerts, setAlerts] = useState<AlertEvt[]>([]);
  const seenRef = useRef<Set<string>>(new Set());
  const initRef = useRef(false);

  const feed = useQuery({
    queryKey: ["alerts-feed"], queryFn: () => feedFn(),
    refetchInterval: live ? 30_000 : false, refetchIntervalInBackground: true,
  });
  const kev = useQuery({
    queryKey: ["alerts-kev"], queryFn: () => kevFn(),
    refetchInterval: live ? 120_000 : false, refetchIntervalInBackground: true,
  });

  useEffect(() => {
    if (!feed.data?.ok && !kev.data?.ok) return;
    const next: AlertEvt[] = [];
    const cves = feed.data?.ok ? feed.data.data.items : [];
    for (const c of cves) {
      const id = c.id || c.cveMetadata?.cveId;
      if (!id || seenRef.current.has("cve:" + id)) continue;
      seenRef.current.add("cve:" + id);
      next.push({
        id: "cve:" + id, kind: "cve", title: id,
        summary: c.summary || c.containers?.cna?.descriptions?.[0]?.value || "New CVE published",
        ts: Date.now(),
      });
    }
    const kevs = kev.data?.ok ? kev.data.data.vulnerabilities : [];
    for (const v of kevs) {
      const id = v.cveID;
      if (!id || seenRef.current.has("kev:" + id)) continue;
      seenRef.current.add("kev:" + id);
      next.push({
        id: "kev:" + id, kind: "kev", title: `${id} — ${v.vendorProject}/${v.product}`,
        summary: v.vulnerabilityName || "Added to CISA KEV catalog", ts: Date.now(),
      });
    }
    if (!next.length) return;
    setAlerts(prev => [...next, ...prev].slice(0, 200));
    if (initRef.current) {
      // Only toast for genuinely new alerts after initial load
      next.slice(0, 3).forEach(a => {
        toast(a.kind === "kev" ? `🚨 KEV: ${a.title}` : `🆕 ${a.title}`, { description: a.summary.slice(0, 140) });
      });
    }
    initRef.current = true;
  }, [feed.data, kev.data]);

  const clear = () => { setAlerts([]); seenRef.current.clear(); initRef.current = false; };

  return (
    <AppShell>
      <PageHeader icon={<BellRing className="size-5" />} title="Real-time Threat Alerts"
        description="Streaming watchtower: polls CVE & CISA KEV feeds and notifies you of new entries as they appear."
        actions={
          <div className="flex items-center gap-2">
            <button onClick={() => setLive(l => !l)} className="inline-flex items-center gap-2 px-3 py-1.5 text-sm rounded-md border border-border hover:bg-secondary">
              {live ? <><Pause className="size-3.5"/> Pause</> : <><Play className="size-3.5"/> Resume</>}
            </button>
            <button onClick={clear} className="inline-flex items-center gap-2 px-3 py-1.5 text-sm rounded-md border border-border hover:bg-secondary">
              <Trash2 className="size-3.5"/> Clear
            </button>
          </div>
        }
      />

      <div className="grid sm:grid-cols-3 gap-4 mb-6">
        <Stat label="Live status" value={live ? "Streaming" : "Paused"} tone={live ? "text-success" : "text-warning"} />
        <Stat label="Alerts buffered" value={alerts.length} tone="text-primary" />
        <Stat label="Polling cycle" value={live ? "30s / 2m" : "—"} tone="text-accent" />
      </div>

      <div className="glass-card overflow-hidden">
        <div className="px-5 py-3 border-b border-border flex items-center gap-2 text-sm">
          <span className={`pulse-dot ${live ? "" : "opacity-30"}`} />
          <span className="font-medium">Alert stream</span>
          <span className="text-muted-foreground text-xs ml-auto font-mono">{new Date().toLocaleTimeString()}</span>
        </div>
        <ul className="divide-y divide-border/60 max-h-[600px] overflow-y-auto">
          {!alerts.length && (
            <li className="p-8 text-center text-muted-foreground text-sm">
              <Bell className="size-8 mx-auto mb-3 opacity-40" />
              Watching feeds… new threats will appear here in real-time.
            </li>
          )}
          {alerts.map(a => (
            <li key={a.id} className="px-5 py-3 hover:bg-secondary/20 transition">
              <div className="flex items-start gap-3">
                <span className={`mt-1 size-2 rounded-full shrink-0 ${a.kind === "kev" ? "bg-destructive" : "bg-primary"}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-mono text-sm font-medium truncate">{a.title}</div>
                    <span className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded ${a.kind === "kev" ? "bg-destructive/10 text-destructive" : "bg-primary/10 text-primary"}`}>{a.kind}</span>
                  </div>
                  <div className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{a.summary}</div>
                  <div className="text-[10px] text-muted-foreground/70 font-mono mt-1">{new Date(a.ts).toLocaleTimeString()}</div>
                </div>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </AppShell>
  );
}

function Stat({ label, value, tone }: { label: string; value: any; tone: string }) {
  return (
    <div className="glass-card p-5">
      <div className="text-xs uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={`text-2xl font-mono font-semibold mt-2 ${tone}`}>{value}</div>
    </div>
  );
}
