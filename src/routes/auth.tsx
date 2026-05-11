import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Shield, LogIn, UserPlus, Loader2 } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/auth")({
  component: AuthPage,
  head: () => ({ meta: [{ title: "Sign in — CyberGita OSINT" }] }),
});

function AuthPage() {
  const nav = useNavigate();
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      if (data.session) nav({ to: "/watchlist" });
    });
  }, [nav]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    try {
      if (mode === "signup") {
        const { error } = await supabase.auth.signUp({
          email, password,
          options: { emailRedirectTo: `${window.location.origin}/watchlist` },
        });
        if (error) throw error;
        toast.success("Account created. Signing you in…");
      }
      const { error } = await supabase.auth.signInWithPassword({ email, password });
      if (error) throw error;
      toast.success("Welcome back, operator.");
      nav({ to: "/watchlist" });
    } catch (e: any) {
      toast.error(e.message || "Auth failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen relative overflow-hidden grid place-items-center px-4 py-10 bg-background">
      {/* 3D animated grid backdrop */}
      <div className="absolute inset-0 -z-10 [perspective:1200px]">
        <div className="absolute inset-x-0 bottom-0 h-[80vh] [transform:rotateX(60deg)_translateZ(-200px)] origin-bottom
          bg-[linear-gradient(to_right,hsl(var(--border))_1px,transparent_1px),linear-gradient(to_bottom,hsl(var(--border))_1px,transparent_1px)]
          bg-[size:48px_48px] opacity-30" />
        <div className="absolute -top-40 -left-40 size-[480px] rounded-full bg-primary/20 blur-3xl animate-pulse" />
        <div className="absolute -bottom-40 -right-40 size-[480px] rounded-full bg-accent/20 blur-3xl animate-pulse" />
      </div>

      <div className="w-full max-w-md">
        <div className="mb-6 flex items-center gap-3">
          <div className="size-11 rounded-md grid place-items-center bg-primary/10 border border-primary/30 shadow-[0_0_30px_-10px_hsl(var(--primary))]">
            <Shield className="size-6 text-primary" />
          </div>
          <div>
            <div className="font-semibold tracking-tight text-lg">CyberGita OSINT</div>
            <div className="text-xs text-muted-foreground font-mono">secure intel access</div>
          </div>
        </div>

        <div className="glass-card p-6 md:p-8 [transform:perspective(1000px)_rotateX(2deg)] hover:[transform:perspective(1000px)_rotateX(0deg)] transition-transform duration-500">
          <div className="flex gap-2 mb-6 p-1 bg-secondary rounded-md">
            <button onClick={() => setMode("login")}
              className={`flex-1 py-1.5 text-sm rounded-md transition ${mode==="login" ? "bg-background border border-border" : "text-muted-foreground"}`}>
              <LogIn className="inline size-3.5 mr-1.5" />Sign in
            </button>
            <button onClick={() => setMode("signup")}
              className={`flex-1 py-1.5 text-sm rounded-md transition ${mode==="signup" ? "bg-background border border-border" : "text-muted-foreground"}`}>
              <UserPlus className="inline size-3.5 mr-1.5" />Sign up
            </button>
          </div>

          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="text-xs text-muted-foreground font-mono">EMAIL</label>
              <input required type="email" value={email} onChange={e=>setEmail(e.target.value)}
                className="mt-1 w-full bg-secondary/50 border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:border-primary" />
            </div>
            <div>
              <label className="text-xs text-muted-foreground font-mono">PASSWORD</label>
              <input required type="password" minLength={6} value={password} onChange={e=>setPassword(e.target.value)}
                className="mt-1 w-full bg-secondary/50 border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:border-primary" />
            </div>
            <button disabled={loading} type="submit"
              className="w-full bg-primary text-primary-foreground rounded-md py-2.5 text-sm font-medium hover:opacity-90 disabled:opacity-50 flex items-center justify-center gap-2">
              {loading && <Loader2 className="size-4 animate-spin" />}
              {mode === "login" ? "Sign in" : "Create account"}
            </button>
          </form>

          <p className="mt-4 text-[11px] text-center text-muted-foreground">
            By continuing you agree to use this OSINT platform responsibly.
          </p>
        </div>

        <div className="mt-4 text-center">
          <Link to="/" className="text-xs text-muted-foreground hover:text-foreground">← Back to dashboard</Link>
        </div>
      </div>
    </div>
  );
}
