import { ReactNode } from "react";

export function ResultCard({ title, subtitle, children, footer }: {
  title?: ReactNode; subtitle?: ReactNode; children: ReactNode; footer?: ReactNode;
}) {
  return (
    <div className="glass-card p-5">
      {(title || subtitle) && (
        <div className="mb-4">
          {title && <h3 className="font-medium">{title}</h3>}
          {subtitle && <p className="text-xs text-muted-foreground mt-0.5 font-mono">{subtitle}</p>}
        </div>
      )}
      {children}
      {footer && <div className="mt-4 pt-4 border-t border-border text-xs text-muted-foreground">{footer}</div>}
    </div>
  );
}

export function KV({ k, v }: { k: string; v: ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-1.5 border-b border-border/60 last:border-0 text-sm">
      <span className="text-muted-foreground">{k}</span>
      <span className="font-mono text-right break-all">{v ?? "—"}</span>
    </div>
  );
}
