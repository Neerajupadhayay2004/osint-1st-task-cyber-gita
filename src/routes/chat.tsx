import { createFileRoute, Link } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useEffect, useRef, useState } from "react";
import { chatSend, type ChatMsg } from "@/lib/chat.functions";
import { analyzeIocs } from "@/lib/ioc.functions";
import { Bot, User, Send, Sparkles, Trash2, Copy, Check, Loader2, Globe, Bug, Server, Mail, ScanSearch, FileSearch, Brain, ArrowLeft, Paperclip, FileText, Wrench, X } from "lucide-react";

export const Route = createFileRoute("/chat")({
  component: ChatPage,
  head: () => ({ meta: [{ title: "AI Analyst Chat · CyberGita" }, { name: "description", content: "Chat with CyberGita's Gemini-powered AI analyst for OSINT, threat intel, CVEs, and recon." }] }),
});

type Msg = ChatMsg & { id: string; ts: number };

const LS_KEY = "cybergita.chat.v1";

const QUICK_PROMPTS = [
  { icon: Globe, label: "Analyze IP 8.8.8.8", text: "Analyze the IP 8.8.8.8 — likely owner, risk, and what CyberGita modules to run." },
  { icon: Bug, label: "Explain Log4Shell", text: "Explain CVE-2021-44228 (Log4Shell): root cause, exploitation, detection, remediation." },
  { icon: Server, label: "Shodan recon plan", text: "Give me a Shodan recon plan for an unknown public IP. Include filters and red flags." },
  { icon: Mail, label: "Email breach triage", text: "How do I triage an email found in multiple breaches? Step by step IR checklist." },
  { icon: ScanSearch, label: "VirusTotal verdict", text: "How should I interpret a VirusTotal score of 5/72 with mixed engine names?" },
  { icon: FileSearch, label: "Subdomain recon", text: "Best methodology for passive subdomain enumeration of a target domain." },
];

function uid() { return Math.random().toString(36).slice(2, 10); }

function ChatPage() {
  const send = useServerFn(chatSend);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [model, setModel] = useState<string>("");
  const [err, setErr] = useState<string>("");
  const [copiedId, setCopiedId] = useState<string>("");
  const [attached, setAttached] = useState<{ name: string; text: string } | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const analyze = useServerFn(analyzeIocs);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(LS_KEY);
      if (raw) setMessages(JSON.parse(raw));
    } catch {}
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    try { localStorage.setItem(LS_KEY, JSON.stringify(messages)); } catch {}
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, busy]);

  async function submit(text: string) {
    const trimmed = text.trim();
    if (!trimmed || busy) return;
    setErr("");
    const userMsg: Msg = { id: uid(), role: "user", content: trimmed, ts: Date.now() };
    const next = [...messages, userMsg];
    setMessages(next);
    setInput("");
    setBusy(true);
    try {
      const res: any = await send({ data: { messages: next.map(({ role, content }) => ({ role, content })) } });
      if (res?.ok) {
        setMessages((m) => [...m, { id: uid(), role: "assistant", content: res.text || "(empty response)", ts: Date.now() }]);
        setModel(res.model || "");
      } else {
        setErr(res?.error || "Unknown error");
      }
    } catch (e: any) {
      setErr(e?.message || "Network error");
    } finally {
      setBusy(false);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }

  function onKey(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); submit(input); }
  }

  function clearChat() {
    setMessages([]);
    setErr("");
    localStorage.removeItem(LS_KEY);
    inputRef.current?.focus();
  }

  async function pickFile(f: File | null) {
    if (!f) return;
    if (f.size > 1_000_000) { setErr("File too large (max 1 MB)"); return; }
    const text = await f.text();
    setAttached({ name: f.name, text });
  }

  async function runIocAnalysis() {
    if (!attached || busy) return;
    setErr("");
    const userMsg: Msg = {
      id: uid(), role: "user", ts: Date.now(),
      content: `📎 Analyze IOC file: **${attached.name}** (${(attached.text.length / 1024).toFixed(1)} KB)`,
    };
    setMessages((m) => [...m, userMsg]);
    setBusy(true);
    try {
      const res: any = await analyze({ data: { text: attached.text, filename: attached.name } });
      if (res?.ok) {
        const i = res.iocs;
        const header = `### 🛡️ IOC Triage Report — \`${attached.name}\`\n\n**Detected:** ${i.ips.length} IPs · ${i.domains.length} domains · ${i.emails.length} emails · ${i.hashes.length} hashes · ${i.cves.length} CVEs · ${i.urls.length} URLs\n\n---\n\n`;
        setMessages((m) => [...m, { id: uid(), role: "assistant", ts: Date.now(), content: header + (res.summary || "(empty)") }]);
        setModel(res.model || "");
      } else {
        setErr(res?.error || "Analysis failed");
      }
    } catch (e: any) {
      setErr(e?.message || "Network error");
    } finally {
      setBusy(false);
      setAttached(null);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  function copy(id: string, text: string) {
    navigator.clipboard?.writeText(text).then(() => {
      setCopiedId(id);
      setTimeout(() => setCopiedId(""), 1200);
    });
  }

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Header */}
      <div className="card-3d edge-4k rounded-xl p-5 md:p-6 relative overflow-hidden">
        <div className="absolute -top-20 -right-20 size-64 bg-primary/20 blur-3xl rounded-full pointer-events-none" />
        <div className="absolute -bottom-20 -left-20 size-64 bg-accent/20 blur-3xl rounded-full pointer-events-none" />
        <div className="relative flex flex-wrap items-center gap-4">
          <div className="size-12 rounded-xl grid place-items-center bg-gradient-to-br from-primary/30 to-accent/30 border border-primary/40 shadow-[0_0_30px_-5px_hsl(var(--primary)/0.5)]">
            <Brain className="size-6 text-primary animate-pulse" />
          </div>
          <div className="flex-1 min-w-0">
            <h1 className="text-2xl md:text-3xl font-bold tracking-tight neon-text">CyberGita AI Analyst</h1>
            <p className="text-sm text-muted-foreground">Gemini-powered chat for OSINT, threat intel, CVEs and recon strategy.</p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Link to="/" className="px-3 py-2 text-xs rounded-md border border-border hover:bg-secondary inline-flex items-center gap-1.5 hover:-translate-x-0.5 transition-transform">
              <ArrowLeft className="size-3.5" /> Back
            </Link>
            {model && <span className="hidden md:inline text-[11px] font-mono text-muted-foreground px-2 py-1 rounded-md border border-border bg-secondary/40">{model}</span>}
            <button onClick={clearChat} className="px-3 py-2 text-xs rounded-md border border-border hover:bg-secondary inline-flex items-center gap-1.5">
              <Trash2 className="size-3.5" /> Clear
            </button>
          </div>
        </div>
      </div>

      {/* Chat surface */}
      <div className="card-3d edge-4k rounded-xl overflow-hidden flex flex-col h-[calc(100vh-22rem)] min-h-[480px]">
        <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 md:p-6 space-y-5 scanline">
          {messages.length === 0 && (
            <div className="h-full grid place-items-center">
              <div className="text-center max-w-xl space-y-5 animate-fade-in">
                <div className="mx-auto size-16 rounded-2xl grid place-items-center bg-gradient-to-br from-primary/20 to-accent/20 border border-primary/30 shadow-[0_10px_40px_-10px_hsl(var(--primary)/0.6)] hover:rotate-6 hover:scale-110 transition-transform duration-500">
                  <Sparkles className="size-7 text-primary" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold mb-1">Ask the analyst anything</h2>
                  <p className="text-sm text-muted-foreground">Paste an IP, hash, CVE, domain or describe a scenario. I'll suggest the right module and explain the data.</p>
                </div>
                <div className="grid sm:grid-cols-2 gap-2 text-left">
                  {QUICK_PROMPTS.map((q) => (
                    <button key={q.label} onClick={() => submit(q.text)}
                      className="group p-3 rounded-lg border border-border bg-card/50 hover:bg-card hover:border-primary/50 hover:-translate-y-0.5 hover:shadow-[0_8px_24px_-8px_hsl(var(--primary)/0.4)] transition-all text-sm flex items-start gap-2.5">
                      <q.icon className="size-4 text-primary mt-0.5 shrink-0 group-hover:scale-110 transition-transform" />
                      <span>{q.label}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          )}
          {messages.map((m) => (
            <MessageBubble key={m.id} msg={m} onCopy={() => copy(m.id, m.content)} copied={copiedId === m.id} />
          ))}
          {busy && (
            <div className="flex gap-3 items-start animate-fade-in">
              <div className="size-8 rounded-lg grid place-items-center bg-primary/15 border border-primary/30 shrink-0">
                <Bot className="size-4 text-primary" />
              </div>
              <div className="px-4 py-3 rounded-xl border border-border bg-card/60 inline-flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="size-4 animate-spin text-primary" />
                Analyzing<span className="inline-flex"><span className="animate-bounce">.</span><span className="animate-bounce" style={{ animationDelay: "120ms" }}>.</span><span className="animate-bounce" style={{ animationDelay: "240ms" }}>.</span></span>
              </div>
            </div>
          )}
          {err && (
            <div className="text-sm text-destructive border border-destructive/40 bg-destructive/10 rounded-lg px-3 py-2">
              {err}
            </div>
          )}
        </div>

        {/* Composer */}
        <div className="border-t border-border bg-background/60 backdrop-blur p-3 md:p-4 space-y-2">
          {attached && (
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg border border-primary/40 bg-primary/10 text-sm animate-fade-in">
              <FileText className="size-4 text-primary shrink-0" />
              <span className="font-mono text-xs truncate flex-1">{attached.name}</span>
              <span className="text-[11px] text-muted-foreground shrink-0">{(attached.text.length / 1024).toFixed(1)} KB</span>
              <button onClick={runIocAnalysis} disabled={busy}
                className="px-2.5 py-1 rounded-md bg-gradient-to-br from-primary to-accent text-primary-foreground text-xs inline-flex items-center gap-1 hover:scale-105 active:scale-95 disabled:opacity-40 transition-transform">
                <Wrench className="size-3" /> Run IOC Analysis
              </button>
              <button onClick={() => { setAttached(null); if (fileRef.current) fileRef.current.value = ""; }}
                className="p-1 rounded-md hover:bg-destructive/20 text-muted-foreground hover:text-destructive">
                <X className="size-3.5" />
              </button>
            </div>
          )}
          <div className="relative rounded-xl border border-border bg-card/60 focus-within:border-primary/60 focus-within:shadow-[0_0_0_3px_hsl(var(--primary)/0.15)] transition-all">
            <textarea ref={inputRef} value={input} onChange={(e) => setInput(e.target.value)} onKeyDown={onKey}
              rows={2}
              placeholder="Ask about an IP, CVE, domain, hash, breach… or attach a CSV/TXT of IOCs"
              className="w-full bg-transparent resize-none px-4 py-3 pl-12 pr-14 text-sm outline-none placeholder:text-muted-foreground" />
            <input ref={fileRef} type="file" accept=".csv,.txt,.log,.json,text/*" className="hidden"
              onChange={(e) => pickFile(e.target.files?.[0] ?? null)} />
            <button onClick={() => fileRef.current?.click()} disabled={busy} title="Attach IOC file (CSV/TXT)"
              className="absolute left-2 bottom-2 size-9 grid place-items-center rounded-lg border border-border bg-secondary/60 hover:bg-secondary hover:border-primary/50 text-muted-foreground hover:text-primary disabled:opacity-40 transition-colors">
              <Paperclip className="size-4" />
            </button>
            <button onClick={() => submit(input)} disabled={busy || !input.trim()}
              className="absolute right-2 bottom-2 size-9 grid place-items-center rounded-lg bg-gradient-to-br from-primary to-accent text-primary-foreground shadow-[0_4px_20px_-4px_hsl(var(--primary)/0.6)] hover:scale-105 active:scale-95 disabled:opacity-40 disabled:hover:scale-100 transition-transform">
              {busy ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
            </button>
          </div>
          <div className="text-[11px] text-muted-foreground font-mono flex flex-wrap gap-x-3 gap-y-1">
            <span>📎 CSV/TXT IOC upload · 🛠 live tool calling · 💾 stored in browser</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function MessageBubble({ msg, onCopy, copied }: { msg: Msg; onCopy: () => void; copied: boolean }) {
  const isUser = msg.role === "user";
  return (
    <div className={`flex gap-3 items-start animate-fade-in ${isUser ? "flex-row-reverse" : ""}`}>
      <div className={`size-8 rounded-lg grid place-items-center shrink-0 border ${isUser ? "bg-accent/20 border-accent/40" : "bg-primary/15 border-primary/30"}`}>
        {isUser ? <User className="size-4 text-accent" /> : <Bot className="size-4 text-primary" />}
      </div>
      <div className={`group max-w-[85%] md:max-w-[78%] ${isUser ? "items-end" : "items-start"} flex flex-col gap-1`}>
        <div className={`px-4 py-3 rounded-2xl text-sm leading-relaxed border whitespace-pre-wrap break-words ${
          isUser
            ? "bg-gradient-to-br from-primary/20 to-accent/15 border-primary/30 rounded-tr-sm shadow-[0_4px_20px_-8px_hsl(var(--primary)/0.4)]"
            : "bg-card/70 border-border rounded-tl-sm"
        }`}>
          <Markdown text={msg.content} />
        </div>
        {!isUser && (
          <button onClick={onCopy} className="opacity-0 group-hover:opacity-100 transition-opacity text-[11px] text-muted-foreground inline-flex items-center gap-1 hover:text-foreground">
            {copied ? <><Check className="size-3 text-success" /> Copied</> : <><Copy className="size-3" /> Copy</>}
          </button>
        )}
      </div>
    </div>
  );
}

// Minimal markdown: code blocks, inline code, bold, lists
function Markdown({ text }: { text: string }) {
  const blocks = text.split(/(```[\s\S]*?```)/g);
  return (
    <>
      {blocks.map((b, i) => {
        if (b.startsWith("```")) {
          const inner = b.replace(/^```[a-zA-Z0-9]*\n?/, "").replace(/```$/, "");
          return (
            <pre key={i} className="my-2 p-3 rounded-lg bg-background/80 border border-border overflow-x-auto text-xs font-mono">
              <code>{inner}</code>
            </pre>
          );
        }
        return <span key={i} dangerouslySetInnerHTML={{ __html: inlineMd(b) }} />;
      })}
    </>
  );
}

function inlineMd(s: string) {
  const esc = s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return esc
    .replace(/`([^`\n]+)`/g, '<code class="px-1.5 py-0.5 rounded bg-background/80 border border-border text-xs font-mono">$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/^\s*[-*]\s+(.+)$/gm, '<div class="flex gap-2"><span class="text-primary">▸</span><span>$1</span></div>')
    .replace(/\n/g, "<br/>");
}
