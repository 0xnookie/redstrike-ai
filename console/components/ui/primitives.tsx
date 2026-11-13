import { ChevronDown } from "lucide-react";
import { cx } from "@/lib/format";
import { SEVERITY, VERDICT, CONFIDENCE, hexA } from "@/lib/theme";
import type { Severity, Verdict, Confidence } from "@/lib/types";

/* ---------- Card = panel (frameless in dark, filled in light) ---------- */
export function Card({ className, children, ...rest }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cx("panel", className)} {...rest}>
      {children}
    </div>
  );
}

/* ---------- Panel + header/body (structured layout) ---------- */
export function Panel({
  className, tall, children, ...rest
}: React.HTMLAttributes<HTMLDivElement> & { tall?: boolean }) {
  return (
    <div className={cx("panel flex flex-col", tall && "tall", className)} {...rest}>
      {children}
    </div>
  );
}

export function PanelHeader({
  title, sub, icon, actions,
}: { title: React.ReactNode; sub?: React.ReactNode; icon?: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <div className="panel-head">
      <div className="flex min-w-0 items-center gap-2.5">
        {icon}
        {/* The title never flex-shrinks — even a sub-pixel shrink makes the browser swap its
            last letters for an ellipsis. It's capped at the row's width instead (a very long
            title still truncates there), and the subtitle absorbs all the squeeze. */}
        <span className="max-w-full shrink-0 truncate text-[15px] font-medium text-fg-strong">{title}</span>
        {sub && <span className="min-w-0 truncate font-mono text-xs text-faint">{sub}</span>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-1.5">{actions}</div>}
    </div>
  );
}

export function PanelBody({
  className, flush, children,
}: { className?: string; flush?: boolean; children: React.ReactNode }) {
  return <div className={cx("panel-body flex-1", flush && "flush", className)}>{children}</div>;
}

/* ---------- View header (crumb · title · live sub · actions) ---------- */
export function ViewHead({
  crumb, title, sub, live, actions,
}: { crumb?: string; title: string; sub?: React.ReactNode; live?: boolean; actions?: React.ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        {crumb && <div className="mb-2 font-mono text-xs tracking-wide text-faint">{crumb}</div>}
        <h1 className="text-[28px] font-semibold leading-tight tracking-tight text-fg-strong sm:text-[30px]">{title}</h1>
        {sub && (
          <div className="mt-2 flex items-center gap-2 font-mono text-[12.5px] text-faint">
            {live && <span className="live-dot" />}
            {sub}
          </div>
        )}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2.5">{actions}</div>}
    </div>
  );
}

export function LivePill({ label = "LIVE" }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/[0.08] px-2.5 py-0.5 font-mono text-[11px] font-medium tracking-wide text-emerald-500">
      <span className="live-dot" />
      {label}
    </span>
  );
}

/* ---------- Select (styled to match inputs: appearance-none + custom chevron) ---------- */
export function Select({
  className, wrapperClassName, children, ...rest
}: React.SelectHTMLAttributes<HTMLSelectElement> & { wrapperClassName?: string }) {
  return (
    <div className={cx("relative inline-flex", wrapperClassName)}>
      <select
        className={cx(
          "h-9 w-full cursor-pointer appearance-none rounded-full border border-line bg-card2 pl-3 pr-8 text-sm text-fg outline-none transition focus:border-fg/40",
          className,
        )}
        {...rest}
      >
        {children}
      </select>
      <ChevronDown size={14} className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-muted" />
    </div>
  );
}

/* ---------- Page header (legacy — used by views not yet migrated) ---------- */
export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-fg-strong">{title}</h1>
        {subtitle && <p className="mt-0.5 text-sm text-muted">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

/* ---------- Pill (colored chip for data: severity / verdict / mappings …) ---------- */
export function Pill({
  label, color = "#94a3b8", dot = false, pulse = false, className,
}: { label: string; color?: string; dot?: boolean; pulse?: boolean; className?: string }) {
  return (
    <span
      className={cx("inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium", className)}
      style={{ color, background: hexA(color, "1f"), border: `1px solid ${hexA(color, "55")}` }}
    >
      {/* pulse: the dot blinks while the thing it labels is live (e.g. a running engagement) */}
      {dot && <span className={cx("h-1.5 w-1.5 rounded-full", pulse && "pulse-dot")} style={{ background: color }} />}
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

/* ---------- Tile / KPI (metric card) ---------- */
export function Kpi({
  label, value, color, sub, note, suffix, icon, onClick, active,
}: {
  label: string; value: React.ReactNode; color?: string; sub?: React.ReactNode; note?: React.ReactNode;
  suffix?: React.ReactNode; icon?: React.ReactNode; onClick?: () => void; active?: boolean;
}) {
  const Comp: any = onClick ? "button" : "div";
  return (
    <Comp
      onClick={onClick}
      className={cx(
        "tile flex min-w-0 flex-col text-left",
        onClick && "cursor-pointer",
        active && "!border-fg/40 ring-1 ring-fg/15",
      )}
    >
      <div className="flex items-center gap-2.5">
        {icon && <span className="tile-ico text-muted" style={color ? { color } : undefined}>{icon}</span>}
        <span className="truncate text-[13px] text-muted">{label}</span>
      </div>
      <div className="mt-3.5 flex items-baseline gap-2">
        <span className="text-[28px] font-semibold leading-none tracking-tight tabular-nums text-fg-strong sm:text-[30px]" style={color ? { color } : undefined}>
          {value}
        </span>
        {suffix && <span className="text-[13px] text-faint">{suffix}</span>}
      </div>
      {(note ?? sub) != null && <div className="mt-2 font-mono text-[11px] text-faint">{note ?? sub}</div>}
    </Comp>
  );
}

/* ---------- Segmented control ---------- */
export function Segmented<T extends string>({
  options, value, onChange,
}: { options: { value: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex rounded-full border border-line bg-card2 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className={cx(
            "rounded-full px-2.5 py-1 text-xs font-medium transition",
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
