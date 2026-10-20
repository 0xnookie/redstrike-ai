import { cx } from "@/lib/format";
import { SEVERITY, VERDICT, CONFIDENCE, hexA } from "@/lib/theme";
import type { Severity, Verdict, Confidence } from "@/lib/types";

/* ---------- Card ---------- */
export function Card({ className, children, ...rest }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cx("rounded-xl border border-line bg-card surface", className)} {...rest}>
      {children}
    </div>
  );
}

/* ---------- Page header ---------- */
export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/* ---------- Pill (colored chip for data: severity / verdict / mappings …) ---------- */
export function Pill({ label, color = "#94a3b8", dot = false, className }: { label: string; color?: string; dot?: boolean; className?: string }) {
  return (
    <span
      className={cx("inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium", className)}
      style={{ color, background: hexA(color, "1f"), border: `1px solid ${hexA(color, "55")}` }}
    >
      {dot && <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />}
      {label}
    </span>
  );
}

export function SeverityBadge({ severity, dot = true }: { severity: Severity; dot?: boolean }) {
  const m = SEVERITY[severity] ?? SEVERITY.info;
  return <Pill label={m.label} color={m.color} dot={dot} />;
}
export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const m = VERDICT[verdict];
  return <Pill label={m.label} color={m.color} dot />;
}
export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  const m = CONFIDENCE[confidence];
  return <Pill label={m.label} color={m.color} />;
}

/* ---------- KPI tile ---------- */
export function Kpi({
  label, value, color, sub, icon, onClick, active,
}: {
  label: string; value: React.ReactNode; color?: string; sub?: React.ReactNode;
  icon?: React.ReactNode; onClick?: () => void; active?: boolean;
}) {
  const Comp: any = onClick ? "button" : "div";
  return (
    <Comp
      onClick={onClick}
      className={cx(
        "flex flex-col rounded-xl border bg-card p-3.5 text-left surface transition",
        onClick && "surface-hover hover:border-brand/40",
        active ? "border-brand/60 ring-1 ring-brand/30" : "border-line"
      )}
    >
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-medium uppercase tracking-wide text-muted">{label}</span>
        {icon && <span className="text-muted">{icon}</span>}
      </div>
      <span className="mt-1 text-2xl font-semibold tabular-nums" style={color ? { color } : undefined}>
        {value}
      </span>
      {sub && <span className="mt-0.5 text-xs text-muted">{sub}</span>}
    </Comp>
  );
}

/* ---------- Segmented control ---------- */
export function Segmented<T extends string>({
  options, value, onChange,
}: { options: { value: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex rounded-lg border border-line bg-card2 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className={cx(
            "rounded-md px-2.5 py-1 text-xs font-medium transition",
            value === o.value ? "bg-brand text-brand-fg shadow-sm" : "text-muted hover:text-fg"
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

/* ---------- Empty state ---------- */
export function EmptyState({ icon, title, hint }: { icon?: React.ReactNode; title: string; hint?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14 text-center">
      {icon && <div className="text-muted/60">{icon}</div>}
      <p className="text-sm font-medium">{title}</p>
      {hint && <p className="max-w-sm text-xs text-muted">{hint}</p>}
    </div>
  );
}

/* ---------- Status dot ---------- */
export function Dot({ color, pulse = false }: { color: string; pulse?: boolean }) {
  return (
    <span className="relative inline-flex h-2 w-2">
      {pulse && <span className="absolute inline-flex h-full w-full animate-pulse-soft rounded-full" style={{ background: color }} />}
      <span className="relative inline-flex h-2 w-2 rounded-full" style={{ background: color }} />
    </span>
  );
}
