import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import { Shield, LayoutDashboard, Globe, Mail, Bug, ShieldAlert, Radio, FileSearch, Bookmark, Activity, Bell, Server, ScanSearch, Menu, X } from "lucide-react";
import { ReactNode, useState, useEffect } from "react";

const nav = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, exact: true },
  { to: "/threat-feed", label: "Threat Feed", icon: Radio },
  { to: "/alerts", label: "Real-time Alerts", icon: Bell },
  { to: "/ip-domain", label: "IP / Domain", icon: Globe },
  { to: "/email-breach", label: "Email Breach", icon: Mail },
  { to: "/cve-search", label: "CVE Search", icon: Bug },
  { to: "/kev", label: "CISA KEV", icon: ShieldAlert },
  { to: "/dns-recon", label: "DNS / Subdomains", icon: FileSearch },
  { to: "/shodan", label: "Shodan", icon: Server },
  { to: "/virustotal", label: "VirusTotal", icon: ScanSearch },
  { to: "/saved", label: "Saved", icon: Bookmark },
];

export default function AppShell({ children }: { children?: ReactNode }) {
  const { location } = useRouterState();
  const [open, setOpen] = useState(false);

  // close drawer on route change
  useEffect(() => { setOpen(false); }, [location.pathname]);

  const SidebarBody = (
    <>
      <div className="p-5 flex items-center gap-2">
        <div className="size-9 rounded-md grid place-items-center bg-primary/10 border border-primary/30">
          <Shield className="size-5 text-primary" />
        </div>
        <div>
          <div className="font-semibold tracking-tight">CyberGita OSINT</div>
          <div className="text-[11px] text-muted-foreground font-mono">v1.1 · live</div>
        </div>
      </div>
      <nav className="px-3 py-2 space-y-0.5 overflow-y-auto">
        {nav.map(({ to, label, icon: Icon, exact }) => {
          const active = exact ? location.pathname === to : location.pathname.startsWith(to);
          return (
            <Link key={to} to={to}
              className={`flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                active ? "bg-sidebar-accent text-foreground border border-border" : "text-sidebar-foreground hover:bg-sidebar-accent/60"
              }`}>
              <Icon className="size-4 opacity-80" />
              <span>{label}</span>
            </Link>
          );
        })}
      </nav>
      <div className="mt-auto p-4 text-xs text-muted-foreground">
        <div className="flex items-center gap-2"><span className="pulse-dot" /> All feeds operational</div>
      </div>
    </>
  );

  return (
    <div className="min-h-screen flex">
      {/* Desktop sidebar */}
      <aside className="hidden md:flex w-64 shrink-0 flex-col bg-sidebar border-r border-sidebar-border sticky top-0 h-screen">
        {SidebarBody}
      </aside>

      {/* Mobile drawer */}
      {open && (
        <div className="md:hidden fixed inset-0 z-50 flex">
          <div className="absolute inset-0 bg-background/80 backdrop-blur-sm" onClick={() => setOpen(false)} />
          <aside className="relative flex w-72 max-w-[85vw] flex-col bg-sidebar border-r border-sidebar-border animate-in slide-in-from-left">
            <button onClick={() => setOpen(false)} className="absolute top-3 right-3 p-1.5 rounded-md hover:bg-sidebar-accent">
              <X className="size-4" />
            </button>
            {SidebarBody}
          </aside>
        </div>
      )}

      {/* Main */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="h-14 border-b border-border flex items-center px-4 md:px-6 gap-3 sticky top-0 z-40 bg-background/85 backdrop-blur-md">
          <button onClick={() => setOpen(true)} className="md:hidden p-2 -ml-2 rounded-md hover:bg-secondary" aria-label="Open menu">
            <Menu className="size-5" />
          </button>
          <div className="md:hidden flex items-center gap-2">
            <Shield className="size-5 text-primary" /> <span className="font-semibold text-sm">CyberGita</span>
          </div>
          <div className="flex-1" />
          <div className="hidden sm:flex items-center gap-2 text-xs text-muted-foreground font-mono">
            <Activity className="size-3.5 text-success" /> live · open intel
          </div>
        </header>
        <main className="flex-1 p-4 md:p-8 max-w-[1400px] w-full mx-auto">
          {children ?? <Outlet />}
        </main>
        <footer className="border-t border-border p-4 text-center text-xs text-muted-foreground">
          Built for Cyber Gita · Open Source Intelligence Platform
        </footer>
      </div>
    </div>
  );
}
