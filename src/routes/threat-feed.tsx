import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useQuery } from "@tanstack/react-query";
import AppShell from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { fetchThreatFeed } from "@/lib/osint.functions";
import { Radio, RefreshCw } from "lucide-react";

export const Route = createFileRoute("/threat-feed")({
  component: Page,
  head: () => ({ meta: [{ title: "Live Threat Feed — CyberGita OSINT" }] }),
});

function Page() {
  const fn = useServerFn(fetchThreatFeed);
  const q = useQuery({ queryKey: ["feed-full"], queryFn: () => fn(), refetchInterval: 60_000 });

  const items = q.data?.ok ? q.data.data.items : [];

  return (
    <AppShell>
      <PageHeader
        icon={<Radio className="size-5" />}
        title="Live Threat Feed"
        description="Recently published CVEs from the NVD (NIST National Vulnerability Database) — last 7 days. Auto-refreshes every minute."
        actions={
          <button onClick={() => q.refetch()} className="inline-flex items-center gap-2 px-3 py-1.5 text-sm rounded-md border border-border hover:bg-secondary">
            <RefreshCw className={`size-3.5 ${q.isFetching ? "animate-spin" : ""}`} /> Refresh
          </button>
        }
      />

      {q.isLoading && <div className="text-sm text-muted-foreground">Loading feed…</div>}
      {q.data && !q.data.ok && <div className="glass-card p-4 text-destructive text-sm">{q.data.error}</div>}

      <div className="grid gap-3">
        {items.map((c: any) => {
          const id = c.id || c.cveMetadata?.cveId;
          const summary = c.summary || c.containers?.cna?.descriptions?.[0]?.value || "";
          const cvss = c.cvss || c.containers?.cna?.metrics?.[0]?.cvssV3_1?.baseScore;
          return (
            <a key={id} href={`https://nvd.nist.gov/vuln/detail/${id}`} target="_blank" rel="noreferrer"
              className="glass-card p-4 hover:border-primary/40 transition block">
              <div className="flex justify-between items-start gap-4">
                <div className="font-mono text-primary">{id}</div>
                {cvss && <span className="text-xs px-2 py-0.5 rounded font-mono bg-destructive/15 text-destructive border border-destructive/30">CVSS {cvss}</span>}
              </div>
              <p className="mt-2 text-sm text-muted-foreground">{summary}</p>
              {c.Modified && <div className="mt-2 text-xs text-muted-foreground font-mono">Modified: {c.Modified}</div>}
            </a>
          );
        })}
      </div>
    </AppShell>
  );
}
