import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import AppShell from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { checkEmailBreach } from "@/lib/osint.functions";
import { Mail, Search, ShieldCheck, AlertTriangle } from "lucide-react";
import { AiAnalysis } from "@/components/AiAnalysis";

export const Route = createFileRoute("/email-breach")({
  component: Page,
  head: () => ({ meta: [{ title: "Email Breach Checker — CyberGita OSINT" }] }),
});

function Page() {
  const fn = useServerFn(checkEmailBreach);
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [res, setRes] = useState<any>(null);

  const run = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setLoading(true); setRes(null);
    try { setRes(await fn({ data: { email } })); }
    finally { setLoading(false); }
  };

  const breaches: any[] = res?.ok ? (res.data?.ExposedBreaches?.breaches_details || []) : [];
  const pastes = res?.ok ? (res.data?.PastesSummary?.cnt || 0) : 0;

  return (
    <AppShell>
      <PageHeader icon={<Mail className="size-5" />} title="Email Breach Checker"
        description="Check if an email address appears in known public data breaches. Powered by XposedOrNot — free, no API key required." />

      <form onSubmit={run} className="glass-card p-4 mb-6 flex gap-2">
        <input type="email" required value={email} onChange={e => setEmail(e.target.value)} placeholder="you@example.com"
          className="flex-1 bg-input border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring" />
        <button disabled={loading} className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-primary text-primary-foreground font-medium hover:opacity-90 disabled:opacity-50">
          <Search className="size-4" /> {loading ? "Checking…" : "Check"}
        </button>
      </form>

      {res && !res.ok && <div className="glass-card p-4 text-destructive text-sm">{res.error}</div>}

      {res?.ok && breaches.length === 0 && (
        <div className="glass-card p-6 text-center">
          <ShieldCheck className="size-10 text-success mx-auto mb-3" />
          <div className="font-medium">No known breaches found</div>
          <p className="text-sm text-muted-foreground mt-1">This email isn't in the public breach corpora we searched.</p>
        </div>
      )}

      {res?.ok && breaches.length > 0 && (
        <>
          <div className="glass-card p-4 mb-4 flex items-center gap-3">
            <AlertTriangle className="size-5 text-destructive" />
            <div>
              <div className="font-medium">Found in {breaches.length} breach{breaches.length > 1 ? "es" : ""} · {pastes} pastes</div>
              <p className="text-xs text-muted-foreground">Recommend changing reused passwords and enabling 2FA.</p>
            </div>
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            {breaches.map((b: any) => (
              <div key={b.breach} className="glass-card p-4">
                <div className="flex justify-between items-start gap-3">
                  <div>
                    <div className="font-medium">{b.breach}</div>
                    <div className="text-xs text-muted-foreground font-mono">{b.domain}</div>
                  </div>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-destructive/15 text-destructive border border-destructive/30">
                    {b.xposed_records?.toLocaleString() || "?"} records
                  </span>
                </div>
                <p className="text-sm text-muted-foreground mt-2 line-clamp-3">{b.details}</p>
                <div className="text-xs text-muted-foreground mt-2 font-mono">
                  Date: {b.xposed_date} · Data: {Array.isArray(b.xposed_data) ? b.xposed_data.join(", ") : b.xposed_data}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {res?.ok && (
        <div className="mt-6">
          <AiAnalysis context="email breach" data={{ email, breaches_count: breaches.length, pastes, breaches: breaches.slice(0,10) }} />
        </div>
      )}
    </AppShell>
  );
}
