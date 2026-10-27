import type { Finding, Verdict } from "./types";

/** classnames helper */
export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

export function fmtDate(s?: string): string {
  if (!s) return "—";
  const d = new Date(s);
  return isNaN(+d) ? s : d.toISOString().slice(0, 10);
}

export function fmtDateTime(s?: string): string {
  if (!s) return "—";
  const d = new Date(s);
  if (isNaN(+d)) return s;
  return d.toISOString().slice(0, 16).replace("T", " ");
}

export function relTime(s?: string): string {
  if (!s) return "";
  const d = new Date(s);
  if (isNaN(+d)) return "";
  const diff = Date.now() - +d;
  const mins = Math.round(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  return `${days}d ago`;
}

export function fmtNum(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\.0$/, "") + "M";
  if (n >= 1_000) return (n / 1_000).toFixed(1).replace(/\.0$/, "") + "k";
  return String(n);
}

export function hostOf(asset: string): string {
  try {
    return new URL(asset).host;
  } catch {
    return (asset || "—").split("/")[0] || "—";
  }
}

/**
 * Every host named in a finding's `asset`. Findings often list several hosts in
 * one field ("a.example.com, b.example.com") — splitting lets per-host views
 * (coverage, risk) attribute the finding to each real host instead of to the
 * whole comma-joined string.
 */
export function assetHosts(asset: string): string[] {
  return (asset || "")
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map(hostOf)
    .filter((h) => h && h !== "—");
}

export function verdictOf(f: Finding): Verdict | "" {
  if (f.review?.verdict) return f.review.verdict;
  if (f.status === "rejected") return "rejected";
  if (f.status === "verified") return "accepted";
  return "";
}

/** A finding that counts toward the report: confirmed (accepted) or
 *  demonstration-limited (blocked), excluding composite kill-chains. */
export function isReportable(f: Finding): boolean {
  if (f.composite) return false;
  const v = verdictOf(f);
  return v === "accepted" || v === "blocked";
}
