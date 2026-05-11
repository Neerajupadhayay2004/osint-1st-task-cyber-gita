import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import AppShell from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { supabase } from "@/integrations/supabase/client";
import { useServerFn } from "@tanstack/react-start";
import { lookupIp, abuseCheck, vtLookup, dnsLookup, checkEmailBreach, searchCves } from "@/lib/osint.functions";
import { downloadCsv, downloadPdf } from "@/lib/export";
import { Bookmark, Plus, Trash2, RefreshCw, Globe, Mail, Bug, Server, Loader2, LogOut, Download, FileText, X, Copy } from "lucide-react";
import { toast } from "sonner";

type Kind = "ip" | "domain" | "email" | "cve";
type Item = { id: string; kind: Kind; value: string; label: string | null; created_at: string };

export const Route = createFileRoute("/watchlist")({
  component: WatchlistPage,
  head: () => ({ meta: [
    { title: "Watchlist — CyberGita OSINT" },
    { name: "description", content: "Save IPs, domains, emails and CVEs. Re-run lookups on demand." },
  ]}),
});

const kindMeta: Record<Kind, { label: string; icon: any; color: string; placeholder: string }> = {
  ip:     { label: "IP Address", icon: Server, color: "text-cyan-400",   placeholder: "e.g. 8.8.8.8" },
  domain: { label: "Domain",     icon: Globe,  color: "text-lime-400",   placeholder: "e.g. example.com" },
  email:  { label: "Email",      icon: Mail,   color: "text-fuchsia-400",placeholder: "e.g. user@host.com" },
  cve:    { label: "CVE",        icon: Bug,    color: "text-amber-400",  placeholder: "e.g. CVE-2024-1234" },
};

function WatchlistPage() {
  const [session, setSession] = useState<any>(null);
  const [ready, setReady] = useState(false);
  const [items, setItems] = useState<Item[]>([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<Kind | "all">("all");
  const [drawer, setDrawer] = useState<{ item: Item; data: any; loading: boolean } | null>(null);

  // Add form
  const [kind, setKind] = useState<Kind>("ip");
  const [value, setValue] = useState("");
  const [label, setLabel] = useState("");
  const [adding, setAdding] = useState(false);

  const ipFn = useServerFn(lookupIp);
  const abuseFn = useServerFn(abuseCheck);
  const vtFn = useServerFn(vtLookup);
  const dnsFn = useServerFn(dnsLookup);
  const breachFn = useServerFn(checkEmailBreach);
  const cveFn = useServerFn(searchCves);

  useEffect(() => {
    const { data: sub } = supabase.auth.onAuthStateChange((_e, s) => setSession(s));
    supabase.auth.getSession().then(({ data }) => { setSession(data.session); setReady(true); });
    return () => sub.subscription.unsubscribe();
  }, []);

  useEffect(() => { if (session) refresh(); }, [session]);

  async function refresh() {
    setLoading(true);
    const { data, error } = await supabase.from("watchlist").select("*").order("created_at", { ascending: false });
    if (error) toast.error(error.message); else setItems((data || []) as Item[]);
    setLoading(false);
  }

  async function add(e: React.FormEvent) {
    e.preventDefault();
    if (!session) return;
    if (!value.trim()) return toast.error("Value required");
    setAdding(true);
    const { error } = await supabase.from("watchlist").insert({
      user_id: session.user.id, kind, value: value.trim(), label: label.trim() || null,
    });
    if (error) toast.error(error.message);
    else { toast.success(`${kindMeta[kind].label} added to watchlist`); setValue(""); setLabel(""); refresh(); }
    setAdding(false);
  }

  async function remove(id: string) {
    const { error } = await supabase.from("watchlist").delete().eq("id", id);
    if (error) toast.error(error.message);
    else { setItems(prev => prev.filter(i => i.id !== id)); toast.success("Removed"); }
  }

  async function rerun(item: Item) {
    setDrawer({ item, data: null, loading: true });
    try {
      let res: any;
      if (item.kind === "ip") {
        const [geo, abuse, vt] = await Promise.all([
          ipFn({ data: { query: item.value } }).catch(e => ({ ok: false, error: e.message })),
          abuseFn({ data: { ip: item.value } }).catch(e => ({ ok: false, error: e.message })),
          vtFn({ data: { kind: "ip", value: item.value } }).catch(e => ({ ok: false, error: e.message })),
        ]);
        res = { geo, abuse, vt };
      } else if (item.kind === "domain") {
        const [dns, vt] = await Promise.all([
          dnsFn({ data: { domain: item.value, type: "ALL" } }).catch(e => ({ ok: false, error: e.message })),
          vtFn({ data: { kind: "domain", value: item.value } }).catch(e => ({ ok: false, error: e.message })),
        ]);
        res = { dns, vt };
      } else if (item.kind === "email") {
        res = { breach: await breachFn({ data: { email: item.value } }).catch(e => ({ ok: false, error: e.message })) };
      } else if (item.kind === "cve") {
        res = { cve: await cveFn({ data: { query: item.value } }).catch(e => ({ ok: false, error: e.message })) };
      }
      setDrawer({ item, data: res, loading: false });
      // persist last result
      await supabase.from("saved_searches").insert({
        user_id: session.user.id, module: `watchlist:${item.kind}`, query: item.value, result: res as any,
      });
    } catch (e: any) {
      toast.error(e.message);
      setDrawer({ item, data: { error: e.message }, loading: false });
    }
  }

  function copy(v: string) { navigator.clipboard.writeText(v); toast.success("Copied"); }

  function exportCsv() {
    if (!items.length) return toast.error("Nothing to export");
    downloadCsv("cybergita-watchlist", items.map(i => ({
      kind: i.kind, value: i.value, label: i.label || "", added: i.created_at,
    })));
  }
  function exportPdf() {
    if (!items.length) return toast.error("Nothing to export");
    downloadPdf({
      title: "Watchlist Report",
      subtitle: `${items.length} monitored assets`,
      sections: [{
        heading: "Tracked Assets",
        columns: ["Kind", "Value", "Label", "Added"],
        rows: items.map(i => [i.kind.toUpperCase(), i.value, i.label || "—", new Date(i.created_at).toLocaleString()]),
      }],
    });
  }

  const filtered = useMemo(() => filter === "all" ? items : items.filter(i => i.kind === filter), [items, filter]);
  const counts = useMemo(() => items.reduce((a, i) => ({ ...a, [i.kind]: (a[i.kind]||0)+1 }), {} as Record<string, number>), [items]);

  if (!ready) {
    return <AppShell><div className="py-20 text-center text-muted-foreground"><Loader2 className="size-5 animate-spin inline mr-2" />Loading…</div></AppShell>;
  }

  if (!session) {
    return (
      <AppShell>
        <PageHeader icon={<Bookmark className="size-5" />} title="Watchlist" description="Save assets and re-run lookups anytime." />
        <div className="glass-card p-10 text-center max-w-lg mx-auto [transform:perspective(900px)_rotateX(3deg)]">
          <div className="size-14 rounded-full bg-primary/10 border border-primary/30 grid place-items-center mx-auto mb-4">
            <Bookmark className="size-6 text-primary" />
          </div>
          <h3 className="font-semibold text-lg">Sign in to manage your watchlist</h3>
          <p className="text-sm text-muted-foreground mt-2">
            Persist IPs, domains, emails and CVEs — re-run intelligence lookups in one click.
          </p>
          <Link to="/auth" className="mt-6 inline-flex items-center gap-2 bg-primary text-primary-foreground px-5 py-2.5 rounded-md text-sm font-medium hover:opacity-90">
            Continue to sign in →
          </Link>
        </div>
      </AppShell>
    );
  }

  return (
    <AppShell>
      <PageHeader
        icon={<Bookmark className="size-5" />}
        title="Watchlist Management"
        description={`Signed in as ${session.user.email}`}
        actions={
          <div className="flex flex-wrap gap-2">
            <button onClick={exportCsv} className="text-xs px-3 py-1.5 rounded-md border border-border hover:bg-secondary inline-flex items-center gap-1.5"><Download className="size-3.5" />CSV</button>
            <button onClick={exportPdf} className="text-xs px-3 py-1.5 rounded-md border border-border hover:bg-secondary inline-flex items-center gap-1.5"><FileText className="size-3.5" />PDF</button>
            <button onClick={() => supabase.auth.signOut()} className="text-xs px-3 py-1.5 rounded-md border border-border hover:bg-secondary inline-flex items-center gap-1.5"><LogOut className="size-3.5" />Sign out</button>
          </div>
        }
      />

      {/* Stats — 3D tilt cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        {(Object.keys(kindMeta) as Kind[]).map(k => {
          const M = kindMeta[k]; const Icon = M.icon;
          return (
            <button key={k} onClick={() => setFilter(filter === k ? "all" : k)}
              className={`glass-card p-4 text-left transition-all duration-300 hover:-translate-y-1 hover:[transform:perspective(800px)_rotateX(-4deg)_translateY(-4px)] ${filter===k ? "ring-2 ring-primary" : ""}`}>
              <Icon className={`size-5 ${M.color} mb-2`} />
              <div className="text-2xl font-semibold">{counts[k] || 0}</div>
              <div className="text-xs text-muted-foreground">{M.label}{(counts[k]||0)!==1?"s":""}</div>
            </button>
          );
        })}
      </div>

      <div className="grid lg:grid-cols-[1fr_360px] gap-6">
        {/* List */}
        <div className="space-y-3 order-2 lg:order-1">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-1 flex-wrap">
              <FilterChip active={filter==="all"} onClick={() => setFilter("all")}>All ({items.length})</FilterChip>
              {(Object.keys(kindMeta) as Kind[]).map(k => (
                <FilterChip key={k} active={filter===k} onClick={() => setFilter(k)}>{kindMeta[k].label}</FilterChip>
              ))}
            </div>
            <button onClick={refresh} disabled={loading} className="text-xs px-3 py-1.5 rounded-md hover:bg-secondary inline-flex items-center gap-1.5">
              <RefreshCw className={`size-3.5 ${loading?"animate-spin":""}`} />Refresh
            </button>
          </div>

          {loading && !items.length ? (
            <div className="glass-card p-10 text-center text-muted-foreground"><Loader2 className="size-5 animate-spin inline mr-2" />Loading…</div>
          ) : filtered.length === 0 ? (
            <div className="glass-card p-10 text-center">
              <Bookmark className="size-8 text-muted-foreground mx-auto mb-3" />
              <p className="text-sm text-muted-foreground">No {filter==="all"?"items":kindMeta[filter as Kind].label.toLowerCase()+"s"} yet. Add your first asset →</p>
            </div>
          ) : (
            <ul className="space-y-2">
              {filtered.map(item => {
                const M = kindMeta[item.kind]; const Icon = M.icon;
                return (
                  <li key={item.id} className="glass-card p-4 group hover:border-primary/40 transition-colors">
                    <div className="flex items-start gap-3">
                      <div className={`size-10 shrink-0 rounded-md grid place-items-center bg-secondary/60 border border-border ${M.color}`}>
                        <Icon className="size-4" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="font-mono text-sm truncate">{item.value}</span>
                          <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-secondary text-muted-foreground">{item.kind}</span>
                        </div>
                        {item.label && <div className="text-xs text-muted-foreground mt-0.5">{item.label}</div>}
                        <div className="text-[11px] text-muted-foreground/70 font-mono mt-1">added {new Date(item.created_at).toLocaleString()}</div>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        <IconBtn onClick={() => copy(item.value)} title="Copy"><Copy className="size-3.5" /></IconBtn>
                        <button onClick={() => rerun(item)} className="text-xs px-2.5 py-1.5 rounded-md bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20 inline-flex items-center gap-1.5">
                          <RefreshCw className="size-3.5" /><span className="hidden sm:inline">Re-run</span>
                        </button>
                        <IconBtn onClick={() => remove(item.id)} title="Delete" danger><Trash2 className="size-3.5" /></IconBtn>
                      </div>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        {/* Add form — 3D card */}
        <div className="order-1 lg:order-2">
          <div className="glass-card p-5 lg:sticky lg:top-20 [transform:perspective(900px)_rotateY(-2deg)] hover:[transform:perspective(900px)_rotateY(0deg)] transition-transform duration-500">
            <div className="flex items-center gap-2 mb-4">
              <div className="size-8 rounded-md grid place-items-center bg-primary/10 border border-primary/30"><Plus className="size-4 text-primary" /></div>
              <h3 className="font-medium">Add to watchlist</h3>
            </div>
            <form onSubmit={add} className="space-y-3">
              <div>
                <label className="text-[11px] text-muted-foreground font-mono">TYPE</label>
                <div className="grid grid-cols-2 gap-1.5 mt-1">
                  {(Object.keys(kindMeta) as Kind[]).map(k => {
                    const M = kindMeta[k]; const Icon = M.icon;
                    return (
                      <button key={k} type="button" onClick={() => setKind(k)}
                        className={`text-xs py-2 rounded-md border inline-flex items-center justify-center gap-1.5 transition ${
                          kind===k ? "border-primary bg-primary/10 text-foreground" : "border-border text-muted-foreground hover:bg-secondary/50"
                        }`}>
                        <Icon className={`size-3.5 ${kind===k ? M.color : ""}`} />{M.label}
                      </button>
                    );
                  })}
                </div>
              </div>
              <div>
                <label className="text-[11px] text-muted-foreground font-mono">VALUE</label>
                <input value={value} onChange={e=>setValue(e.target.value)} placeholder={kindMeta[kind].placeholder}
                  className="mt-1 w-full bg-secondary/50 border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:border-primary" />
              </div>
              <div>
                <label className="text-[11px] text-muted-foreground font-mono">LABEL (optional)</label>
                <input value={label} onChange={e=>setLabel(e.target.value)} placeholder="e.g. corp office VPN"
                  className="mt-1 w-full bg-secondary/50 border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:border-primary" />
              </div>
              <button disabled={adding} type="submit"
                className="w-full bg-primary text-primary-foreground rounded-md py-2.5 text-sm font-medium hover:opacity-90 disabled:opacity-50 inline-flex items-center justify-center gap-2">
                {adding ? <Loader2 className="size-4 animate-spin" /> : <Plus className="size-4" />}Add asset
              </button>
            </form>
          </div>
        </div>
      </div>

      {/* Re-run drawer */}
      {drawer && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <div className="absolute inset-0 bg-background/70 backdrop-blur-sm" onClick={() => setDrawer(null)} />
          <div className="relative w-full sm:max-w-2xl bg-background border-l border-border overflow-y-auto animate-in slide-in-from-right">
            <div className="sticky top-0 bg-background/95 backdrop-blur border-b border-border px-5 py-3 flex items-center justify-between">
              <div>
                <div className="text-xs text-muted-foreground font-mono">RE-RUN · {drawer.item.kind.toUpperCase()}</div>
                <div className="font-mono text-sm">{drawer.item.value}</div>
              </div>
              <button onClick={() => setDrawer(null)} className="p-2 rounded-md hover:bg-secondary"><X className="size-4" /></button>
            </div>
            <div className="p-5">
              {drawer.loading ? (
                <div className="py-10 text-center text-muted-foreground"><Loader2 className="size-6 animate-spin inline mr-2" />Running fresh lookups…</div>
              ) : (
                <pre className="text-[11px] leading-relaxed font-mono bg-secondary/40 border border-border rounded-md p-4 overflow-auto max-h-[70vh]">
{JSON.stringify(drawer.data, null, 2)}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </AppShell>
  );
}

function FilterChip({ active, onClick, children }: any) {
  return (
    <button onClick={onClick}
      className={`text-xs px-3 py-1.5 rounded-full border transition ${
        active ? "bg-primary/10 border-primary/40 text-foreground" : "border-border text-muted-foreground hover:bg-secondary"
      }`}>{children}</button>
  );
}
function IconBtn({ children, onClick, title, danger }: any) {
  return (
    <button onClick={onClick} title={title}
      className={`p-2 rounded-md hover:bg-secondary ${danger ? "text-muted-foreground hover:text-destructive" : "text-muted-foreground hover:text-foreground"}`}>
      {children}
    </button>
  );
}
