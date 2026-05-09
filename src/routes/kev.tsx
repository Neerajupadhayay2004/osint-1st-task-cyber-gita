import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useQuery } from "@tanstack/react-query";
import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { fetchKev } from "@/lib/osint.functions";
import { ShieldAlert, Download } from "lucide-react";

export const Route = createFileRoute("/kev")({
  component: Page,
  head: () => ({ meta: [{ title: "CISA KEV Catalog — CyberGita OSINT" }] }),
});

function Page() {
  const fn = useServerFn(fetchKev);
  const q = useQuery({ queryKey: ["kev-full"], queryFn: () => fn(), staleTime: 600_000 });
  const [filter, setFilter] = useState("");

  const list = q.data?.ok ? q.data.data.vulnerabilities : [];
  const filtered = useMemo(() => {
    const f = filter.toLowerCase();
    if (!f) return list;
    return list.filter((v: any) => [v.cveID, v.vendorProject, v.product, v.vulnerabilityName].some((s: string) => s?.toLowerCase().includes(f)));
  }, [list, filter]);

  const exportCsv = () => {
    const rows = [["cveID", "vendor", "product", "vulnerability", "dateAdded", "dueDate"]];
    filtered.forEach((v: any) => rows.push([v.cveID, v.vendorProject, v.product, v.vulnerabilityName, v.dateAdded, v.dueDate]));
    const csv = rows.map(r => r.map(c => `"${(c || "").replace(/"/g, '""')}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "kev.csv"; a.click();
  };

  return (
    <AppShell>
      <PageHeader icon={<ShieldAlert className="size-5" />} title="CISA Known Exploited Vulnerabilities"
        description="Vulnerabilities actively being exploited in the wild, as catalogued by CISA. Update cycle: continuous."
        actions={
          <button onClick={exportCsv} className="inline-flex items-center gap-2 px-3 py-1.5 text-sm rounded-md border border-border hover:bg-secondary">
            <Download className="size-3.5" /> Export CSV
          </button>
        }
      />

      <div className="glass-card p-4 mb-4 flex items-center gap-3">
        <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter by CVE, vendor, product…"
          className="flex-1 bg-input border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring" />
        <span className="text-sm text-muted-foreground font-mono whitespace-nowrap">{filtered.length} / {list.length}</span>
      </div>

      <div className="glass-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-secondary/40 text-xs uppercase tracking-wider text-muted-foreground">
              <tr>
                <th className="text-left px-4 py-3">CVE</th>
                <th className="text-left px-4 py-3">Vendor</th>
                <th className="text-left px-4 py-3">Product</th>
                <th className="text-left px-4 py-3">Vulnerability</th>
                <th className="text-left px-4 py-3 whitespace-nowrap">Date Added</th>
                <th className="text-left px-4 py-3 whitespace-nowrap">Due Date</th>
              </tr>
            </thead>
            <tbody>
              {q.isLoading && <tr><td colSpan={6} className="p-6 text-center text-muted-foreground">Loading catalog…</td></tr>}
              {filtered.slice(0, 100).map((v: any) => (
                <tr key={v.cveID} className="border-t border-border/60 hover:bg-secondary/20">
                  <td className="px-4 py-2.5 font-mono text-destructive whitespace-nowrap">
                    <a href={`https://nvd.nist.gov/vuln/detail/${v.cveID}`} target="_blank" rel="noreferrer" className="hover:underline">{v.cveID}</a>
                  </td>
                  <td className="px-4 py-2.5">{v.vendorProject}</td>
                  <td className="px-4 py-2.5">{v.product}</td>
                  <td className="px-4 py-2.5 max-w-md truncate" title={v.vulnerabilityName}>{v.vulnerabilityName}</td>
                  <td className="px-4 py-2.5 font-mono text-xs">{v.dateAdded}</td>
                  <td className="px-4 py-2.5 font-mono text-xs">{v.dueDate}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </AppShell>
  );
}
