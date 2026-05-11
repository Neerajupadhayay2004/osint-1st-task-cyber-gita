import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import AppShell from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { dnsLookup, lookupCertificates, rdapLookup } from "@/lib/osint.functions";
import { FileSearch, Search } from "lucide-react";
import { AiAnalysis } from "@/components/AiAnalysis";

export const Route = createFileRoute("/dns-recon")({
  component: Page,
  head: () => ({ meta: [{ title: "DNS & Subdomain Recon — CyberGita OSINT" }] }),
});

function Page() {
  const dnsFn = useServerFn(dnsLookup);
  const crtFn = useServerFn(lookupCertificates);
  const rdapFn = useServerFn(rdapLookup);
  const [domain, setDomain] = useState("github.com");
  const [loading, setLoading] = useState(false);
  const [dns, setDns] = useState<any>(null);
  const [certs, setCerts] = useState<any>(null);
  const [rdap, setRdap] = useState<any>(null);

  const run = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setLoading(true); setDns(null); setCerts(null); setRdap(null);
    const [d, c, r] = await Promise.all([
      dnsFn({ data: { domain, type: "ALL" } }),
      crtFn({ data: { domain } }),
      rdapFn({ data: { domain } }),
    ]);
    setDns(d); setCerts(c); setRdap(r);
    setLoading(false);
  };

  return (
    <AppShell>
      <PageHeader icon={<FileSearch className="size-5" />} title="DNS & Subdomain Recon"
        description="Resolve DNS records (Cloudflare DoH), enumerate subdomains via Certificate Transparency (crt.sh), and inspect RDAP registration data." />

      <form onSubmit={run} className="glass-card p-4 mb-6 flex gap-2">
        <input value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com"
          className="flex-1 bg-input border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring" />
        <button disabled={loading} className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-primary text-primary-foreground font-medium hover:opacity-90 disabled:opacity-50">
          <Search className="size-4" /> {loading ? "Scanning…" : "Recon"}
        </button>
      </form>

      <div className="grid md:grid-cols-2 gap-4 mb-4">
        <div className="glass-card p-5">
          <h3 className="font-medium mb-3">DNS Records</h3>
          {!dns && <p className="text-sm text-muted-foreground">Submit a domain to begin.</p>}
          {dns?.ok && Object.entries(dns.data).map(([type, recs]: any) => (
            <div key={type} className="mb-3">
              <div className="text-xs uppercase tracking-wider text-muted-foreground mb-1">{type}</div>
              {(recs as any[]).length === 0 && <div className="text-xs text-muted-foreground/60">none</div>}
              {(recs as any[]).map((r, i) => (
                <div key={i} className="text-xs font-mono break-all py-0.5">{r.data}</div>
              ))}
            </div>
          ))}
          {dns && !dns.ok && <div className="text-destructive text-sm">{dns.error}</div>}
        </div>

        <div className="glass-card p-5">
          <h3 className="font-medium mb-3">Subdomains <span className="text-xs text-muted-foreground font-mono">(crt.sh CT logs)</span></h3>
          {!certs && <p className="text-sm text-muted-foreground">Submit a domain to begin.</p>}
          {certs?.ok && (
            <>
              <div className="text-xs text-muted-foreground mb-2 font-mono">{certs.data.subdomains.length} unique · {certs.data.total} certs</div>
              <div className="max-h-72 overflow-y-auto space-y-0.5">
                {certs.data.subdomains.map((s: string) => (
                  <div key={s} className="text-xs font-mono break-all py-0.5 border-b border-border/40 last:border-0">{s}</div>
                ))}
              </div>
            </>
          )}
          {certs && !certs.ok && <div className="text-destructive text-sm">{certs.error}</div>}
        </div>
      </div>

      <div className="glass-card p-5">
        <h3 className="font-medium mb-3">RDAP Registration</h3>
        {!rdap && <p className="text-sm text-muted-foreground">Submit a domain to begin.</p>}
        {rdap?.ok && (
          <pre className="text-xs font-mono bg-input/50 p-3 rounded-md overflow-x-auto max-h-72 border border-border">
            {JSON.stringify(rdap.data, null, 2)}
          </pre>
        )}
        {rdap && !rdap.ok && <div className="text-destructive text-sm">{rdap.error}</div>}
      </div>

      {(dns?.ok || certs?.ok) && (
        <div className="mt-6">
          <AiAnalysis context="DNS / subdomain recon" data={{
            domain,
            dns: dns?.ok ? dns.data : null,
            subdomains_sample: certs?.ok ? certs.data.subdomains.slice(0,30) : [],
            subdomain_count: certs?.ok ? certs.data.subdomains.length : 0,
          }} />
        </div>
      )}
    </AppShell>
  );
}
