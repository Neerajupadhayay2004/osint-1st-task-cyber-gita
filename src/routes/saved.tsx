import { createFileRoute } from "@tanstack/react-router";
import AppShell from "@/components/AppShell";
import { PageHeader } from "@/components/PageHeader";
import { Bookmark, Info } from "lucide-react";

export const Route = createFileRoute("/saved")({
  component: Page,
  head: () => ({ meta: [{ title: "Saved Searches — CyberGita OSINT" }] }),
});

function Page() {
  return (
    <AppShell>
      <PageHeader icon={<Bookmark className="size-5" />} title="Saved Searches & Watchlist"
        description="Your investigation history and monitored assets." />
      <div className="glass-card p-8 text-center">
        <Info className="size-8 text-muted-foreground mx-auto mb-3" />
        <h3 className="font-medium">Sign in to save searches</h3>
        <p className="text-sm text-muted-foreground mt-1 max-w-md mx-auto">
          Authentication is wired into the backend (Lovable Cloud). Ask to add the login UI next and your lookups will be persisted per user.
        </p>
      </div>
    </AppShell>
  );
}
