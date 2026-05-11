import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import AppShell from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { ResultCard, KV } from "@/components/ResultCard";
import { lookupIp } from "@/lib/osint.functions";
import { Globe, Search, ShieldAlert, Cpu, Activity, FileText } from "lucide-react";

export const Route = createFileRoute("/ip-domain")({
  component: Page,
  head: () => ({ meta: [{ title: "IP & Domain Lookup — CyberGita OSINT" }] }),
});

function Page() {
  const fn = useServerFn(lookupIp);
  const [q, setQ] = useState("8.8.8.8");
  const [loading, setLoading] = useState(false);
  const [res, setRes] = useState<any>(null);
  const [showRaw, setShowRaw] = useState(false);

  const run = async (e?: React.FormEvent) => {
    e?.preventDefault();
    setLoading(true); setRes(null);
    try { setRes(await fn({ data: { query: q } })); }
    finally { setLoading(false); }
  };

  // Standardized Backend Data Check
  const hasData = res?.ok && res.data.summary;
  const s = hasData ? res.data.summary : null;
  const n = hasData ? res.data.network : res?.data;
  const ai = hasData ? res.data.ai_intelligence : null;

  return (
    <AppShell>
      <PageHeader icon={<Globe className="size-5" />} title="IP / Domain Intelligence"
        description="Unified OSINT analysis with AI threat scoring and deep intelligence reports." />

      <form onSubmit={run} className="glass-card p-4 mb-6 flex gap-2">
        <input value={q} onChange={e => setQ(e.target.value)} placeholder="IP address or domain (e.g., 8.8.8.8 or github.com)"
          className="flex-1 bg-input border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-ring" />
        <button disabled={loading} className="inline-flex items-center gap-2 px-6 py-2 rounded-md bg-primary text-primary-foreground font-medium hover:opacity-90 transition-all disabled:opacity-50">
          <Search className="size-4" /> {loading ? "Analyzing..." : "Analyze Target"}
        </button>
      </form>

      {res && !res.ok && (
        <div className="glass-card p-4 border-l-4 border-destructive bg-destructive/10 text-destructive text-sm mb-6">
          <div className="font-bold mb-1">Analysis Failed</div>
          {res.error}
        </div>
      )}
      
      {hasData && (
        <div className="flex flex-col gap-6 mb-6 animate-in fade-in slide-in-from-bottom-2 duration-500">
          {/* Security Status Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className={`glass-card p-5 border-t-4 transition-all ${s.is_malicious ? 'border-destructive bg-destructive/5' : 'border-success bg-success/5'}`}>
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1 font-bold">Security Status</div>
              <div className={`text-xl font-black ${s.is_malicious ? 'text-destructive' : 'text-success'}`}>
                {s.is_malicious ? '🔴 MALICIOUS' : '✅ CLEAN'}
              </div>
              <div className="text-[9px] text-muted-foreground mt-1 uppercase font-mono">Real-time check</div>
            </div>
            
            <div className="glass-card p-5 border-t-4 border-primary">
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1 font-bold">Risk Score</div>
              <div className="text-xl font-mono font-bold">{s.threat_score} <span className="text-xs text-muted-foreground font-normal">/ 1.0</span></div>
              <div className={`text-[9px] uppercase font-bold mt-1 ${s.threat_level === 'critical' ? 'text-destructive' : s.threat_level === 'high' ? 'text-warning' : 'text-success'}`}>
                {s.threat_level} Priority
              </div>
            </div>
            
            <div className="glass-card p-5 border-t-4 border-accent">
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1 font-bold">Whitelisted</div>
              <div className={`text-xl font-bold ${s.is_whitelisted ? 'text-success' : 'text-muted-foreground'}`}>
                {s.is_whitelisted ? 'TRUE' : 'FALSE'}
              </div>
              <div className="text-[9px] text-muted-foreground mt-1 uppercase font-mono">AbuseIPDB Verified</div>
            </div>
            
            <div className="glass-card p-5 border-t-4 border-warning">
              <div className="text-[10px] uppercase tracking-widest text-muted-foreground mb-1 font-bold">Detections</div>
              <div className="text-xl font-mono font-bold">{s.total_detections}</div>
              <div className="text-[9px] text-muted-foreground mt-1 uppercase font-mono">Security Vendors</div>
            </div>
          </div>

          {/* AI Intelligence Section */}
          <div className="grid md:grid-cols-2 gap-6">
            <div className="glass-card p-6 border-l-4 border-accent bg-accent/5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-bold flex items-center gap-2"><Cpu className="size-4 text-accent" /> AI Security Classifier</h3>
                <span className="text-[10px] bg-accent/20 px-2 py-0.5 rounded text-accent uppercase font-bold">Local ML</span>
              </div>
              <div className="text-sm font-bold mb-2 flex items-center gap-2">
                {ai.classifier.threat ? (
                  <><ShieldAlert className="size-4 text-destructive" /> <span className="text-destructive">Threat Pattern Detected</span></>
                ) : (
                  <><Activity className="size-4 text-success" /> <span className="text-success">Traffic Pattern Safe</span></>
                )}
              </div>
              <p className="text-xs text-muted-foreground italic mb-4">"{ai.classifier.text}"</p>
              <div className="flex items-center gap-4">
                <div className="flex-1 bg-secondary h-1.5 rounded-full overflow-hidden">
                  <div className="bg-accent h-full transition-all" style={{ width: `${(ai.classifier.confidence || 0) * 100}%` }} />
                </div>
                <span className="text-[10px] font-mono font-bold text-muted-foreground">{Math.round((ai.classifier.confidence || 0) * 100)}% CONFIDENCE</span>
              </div>
            </div>

            {ai.gemini_report && !ai.gemini_report.error && (
              <div className="glass-card p-6 border-l-4 border-blue-500 bg-blue-500/5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-bold flex items-center gap-2 text-blue-500"><ShieldAlert className="size-4" /> Gemini Deep Intel</h3>
                  <span className="text-[10px] bg-blue-500/20 px-2 py-0.5 rounded text-blue-500 uppercase font-bold">Expert View</span>
                </div>
                <p className="text-sm mb-3 font-bold text-blue-500/90">{ai.gemini_report.summary}</p>
                <div className="text-xs text-muted-foreground leading-relaxed line-clamp-4">{ai.gemini_report.risk_assessment}</div>
              </div>
            )}
          </div>

          {/* Network & Geo Grid */}
          <div className="grid md:grid-cols-2 gap-4">
            <ResultCard title="Network Intelligence" subtitle="ISP and Infrastructure data">
              <KV k="Target Host" v={res.data.target} />
              <KV k="Internet Service Provider" v={n.isp || "N/A"} />
              <KV k="Organization" v={n.org || "N/A"} />
              <KV k="Autonomous System" v={n.asn || "N/A"} />
              {n.ports && n.ports.length > 0 && (
                <KV k="Open Network Ports" v={n.ports.join(", ")} />
              )}
            </ResultCard>
            
            <ResultCard title="Global Context" subtitle="Physical location of target">
              <KV k="Country" v={n.country || "Unknown Origin"} />
              <KV k="Region / City" v={n.city || "N/A"} />
              <KV k="Infrastructure Timezone" v={n.timezone || "N/A"} />
              {n.lat && <KV k="Geo Coordinates" v={`${n.lat}, ${n.lon}`} />}
            </ResultCard>
          </div>

          {/* Professional Recommendations from Gemini AI */}
          {ai.gemini_report && !ai.gemini_report.error && (
            <div className="glass-card p-6 border-t-4 border-blue-500/30">
              <h3 className="text-sm font-bold uppercase tracking-widest text-blue-500 mb-4 flex items-center gap-2">
                <FileText className="size-4" /> Actionable Recommendations
              </h3>
              <div className="grid sm:grid-cols-2 gap-4">
                {ai.gemini_report.recommendations.map((rec: string, i: number) => (
                  <div key={i} className="flex gap-3 p-3 rounded-lg bg-secondary/30 border border-border/50 text-xs text-muted-foreground">
                    <div className="size-5 rounded-full bg-blue-500/10 text-blue-500 grid place-items-center flex-shrink-0 font-bold">{i+1}</div>
                    {rec}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Raw Data Toggle */}
          <div className="flex justify-center mt-4">
            <button 
              onClick={() => setShowRaw(!showRaw)}
              className="text-[10px] uppercase tracking-widest text-muted-foreground hover:text-primary transition font-bold"
            >
              {showRaw ? 'Hide Raw JSON Data' : 'View Raw Intelligence Data'}
            </button>
          </div>

          {showRaw && (
            <div className="glass-card p-4 overflow-x-auto">
              <pre className="text-[10px] font-mono text-muted-foreground">{JSON.stringify(res.data.raw_sources, null, 2)}</pre>
            </div>
          )}
        </div>
      )}
    </AppShell>
  );
}



