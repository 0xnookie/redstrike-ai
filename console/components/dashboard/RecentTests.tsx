"use client";

import Link from "next/link";
import { ArrowUpRight, FlaskConical } from "lucide-react";
import { Card, EmptyState, Dot } from "@/components/ui/primitives";
import { relTime } from "@/lib/format";
import { SEVERITY } from "@/lib/theme";
import type { TestRun } from "@/lib/types";

const STATUS: Record<TestRun["status"], { label: string; color: string }> = {
  running: { label: "Running", color: "#3b82f6" },
  completed: { label: "Completed", color: "#22c55e" },
  failed: { label: "Failed", color: "#ef4444" },
  queued: { label: "Queued", color: "#9ca3af" },
};

/** The most recent pentest runs for the active engagement. Empty → call to action. */
export function RecentTests({ tests }: { tests: TestRun[] }) {
  const recent = [...tests]
    .sort((a, b) => +new Date(b.startedAt) - +new Date(a.startedAt))
    .slice(0, 6);

  return (
    <Card className="flex flex-col p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold">Recent Tests</h2>
        <Link href="/activity" className="inline-flex items-center gap-1 text-xs text-muted hover:text-fg">
          View all <ArrowUpRight size={13} />
        </Link>
      </div>

      {recent.length === 0 ? (
        <EmptyState icon={<FlaskConical size={22} />} title="No tests yet" hint="Run your first pentest to see results here" />
      ) : (
        <ul className="divide-y divide-line">
          {recent.map((t) => {
            const st = STATUS[t.status];
            const sev = t.topSeverity ? SEVERITY[t.topSeverity] : SEVERITY.info;
            return (
              <li key={t.id} className="flex items-center gap-3 py-2.5">
                <Dot color={st.color} pulse={t.status === "running"} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">{t.profile ?? "Pentest run"}</div>
                  <div className="truncate font-mono text-[11px] text-muted">
                    {t.target} · {relTime(t.startedAt)}
                  </div>
                </div>
                {typeof t.findings === "number" && t.findings > 0 && (
                  <span className="shrink-0 text-xs tabular-nums" style={{ color: sev.color }}>
                    {t.findings} finding{t.findings === 1 ? "" : "s"}
                  </span>
                )}
                <span className="w-[72px] shrink-0 text-right text-[11px] text-muted">{st.label}</span>
              </li>
            );
          })}
        </ul>
      )}
    </Card>
  );
}
