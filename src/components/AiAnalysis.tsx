import { useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { aiAnalyze } from "@/lib/osint.functions";
import { Sparkles, Loader2, AlertTriangle } from "lucide-react";

export function AiAnalysis({ context, data }: { context: string; data: any }) {
  const fn = useServerFn(aiAnalyze);
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [result, setResult] = useState<any>(null);
  const [err, setErr] = useState<string>("");

  async function run() {
    setState("loading"); setErr("");
    try {
      const res: any = await fn({ data: { context, data } });
      if (res?.ok) { setResult(res.data); setState("done"); }
      else { setErr(res?.error || "Unknown error"); setState("error"); }
    } catch (e: any) { setErr(e.message); setState("error"); }
  }

  if (state === "idle") {
    return (
      <button onClick={run}
        className="card-3d w-full p-4 flex items-center justify-center gap-2 text-sm font-medium group neon-text">
        <Sparkles className="size-4 text-primary group-hover:rotate-12 transition-transform float-3d" />
        Analyze with Gemini AI
      </button>
    );
  }

  if (state === "loading") {
    return (
      <div className="card-3d scanline relative p-6 text-center overflow-hidden">
        <Loader2 className="size-5 animate-spin inline mr-2 text-primary" />
        <span className="text-sm text-muted-foreground">AI is analyzing the intelligence…</span>
      </div>
    );
  }

  if (state === "error") {
    return (
      <div className="card-3d edge-4k p-4 border-l-4 border-destructive bg-destructive/5 text-sm">
        <div className="flex items-center gap-2 text-destructive font-medium"><AlertTriangle className="size-4" />AI analysis failed</div>
        <div className="text-xs text-muted-foreground mt-1">{err}</div>
        <button onClick={run} className="mt-2 text-xs underline hover:text-primary">Retry</button>
      </div>
    );
  }

  const sevColor =
    result?.severity === "critical" ? "text-destructive border-destructive/40 bg-destructive/5" :
    result?.severity === "high"     ? "text-warning border-warning/40 bg-warning/5" :
    result?.severity === "medium"   ? "text-accent border-accent/40 bg-accent/5" :
                                      "text-success border-success/40 bg-success/5";

  return (
    <div className="card-3d scanline relative p-5 border-l-4 border-primary/40 bg-primary/5 animate-in fade-in slide-in-from-bottom-2">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2">
          <div className="size-8 rounded-md grid place-items-center bg-primary/10 border border-primary/30">
            <Sparkles className="size-4 text-primary" />
          </div>
          <div>
            <div className="font-semibold text-sm">Gemini AI Analysis</div>
            <div className="text-[10px] text-muted-foreground font-mono uppercase">{context}</div>
          </div>
        </div>
        {result?.severity && (
          <span className={`text-[10px] uppercase font-bold px-2 py-1 rounded border ${sevColor}`}>
            {result.severity}
          </span>
        )}
      </div>

      <p className="text-sm font-medium mb-2">{result?.summary}</p>
      <p className="text-xs text-muted-foreground leading-relaxed mb-4">{result?.risk_assessment}</p>

      {result?.key_findings?.length > 0 && (
        <div className="mb-4">
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2 font-mono">Key findings</div>
          <ul className="space-y-1.5">
            {result.key_findings.map((f: string, i: number) => (
              <li key={i} className="text-xs flex gap-2">
                <span className="text-primary">›</span><span className="text-muted-foreground">{f}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {result?.recommendations?.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2 font-mono">Recommended actions</div>
          <div className="grid sm:grid-cols-2 gap-2">
            {result.recommendations.map((r: string, i: number) => (
              <div key={i} className="text-xs p-2.5 rounded-md bg-secondary/40 border border-border/60 flex gap-2">
                <span className="size-4 rounded-full bg-primary/15 text-primary grid place-items-center text-[10px] font-bold shrink-0">{i+1}</span>
                <span className="text-muted-foreground">{r}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
