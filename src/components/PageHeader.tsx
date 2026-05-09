import { ReactNode } from "react";

export function PageHeader({ icon, title, description, actions }: {
  icon?: ReactNode; title: string; description?: string; actions?: ReactNode;
}) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
      <div className="flex items-start gap-3">
        {icon && <div className="size-10 rounded-md grid place-items-center bg-primary/10 border border-primary/30 text-primary">{icon}</div>}
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          {description && <p className="text-sm text-muted-foreground mt-1 max-w-2xl">{description}</p>}
        </div>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}
