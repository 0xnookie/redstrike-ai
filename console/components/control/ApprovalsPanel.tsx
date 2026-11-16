"use client";

import { useEffect, useState } from "react";
import { ShieldQuestion, Check, CheckCheck, Play, Loader2 } from "lucide-react";
import { useControl } from "./ControlProvider";
import { Card, EmptyState } from "@/components/ui/primitives";
import { cx, relTime } from "@/lib/format";
import { useToast } from "@/components/ui/Toast";

export function ApprovalsPanel() {
  const { pending, busy, running, doApprove, doResume } = useControl();
  const toast = useToast();
  const [sel, setSel] = useState<Set<string>>(new Set());

  // drop selections for items that are no longer pending (approved / resumed away)
  useEffect(() => {
    setSel((prev) => {
      const live = new Set(pending.map((p) => p.fingerprint));
      const next = new Set<string>();
      prev.forEach((fp) => live.has(fp) && next.add(fp));
      return next.size === prev.size ? prev : next;
    });
  }, [pending]);

  const toggle = (fp: string) =>
    setSel((prev) => {
      const next = new Set(prev);
      next.has(fp) ? next.delete(fp) : next.add(fp);
      return next;
    });

  const approveSelected = async () => {
    if (!sel.size) return;
    const n = sel.size;
    if (await doApprove([...sel])) toast(`Approved ${n} action${n === 1 ? "" : "s"} — resume to run ${n === 1 ? "it" : "them"}`);
    setSel(new Set());
  };
  const approveAll = async () => {
    const n = pending.length;
    if (await doApprove("all")) toast(`Approved all ${n} pending action${n === 1 ? "" : "s"}`);
  };

  return (
    <Card className="flex flex-col">
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          <ShieldQuestion size={15} className="text-brand" /> Approvals
          {pending.length > 0 && (
            <span className="rounded-full bg-amber-500/15 px-1.5 py-0.5 text-[11px] font-medium text-amber-400">{pending.length}</span>
          )}
        </h2>
        {pending.length > 0 && (
          <button
            onClick={() => void approveAll()}
            disabled={busy}
            className="inline-flex items-center gap-1 text-xs font-medium text-muted transition hover:text-fg disabled:opacity-60"
          >
            <CheckCheck size={13} /> Approve all
          </button>
        )}
      </div>

      {pending.length === 0 ? (
        <EmptyState
          icon={<ShieldQuestion size={22} />}
          title="Nothing awaiting approval"
          hint="Autonomous runs clear every in-scope command on their own. Only a Supervised run pauses a command outside its allowlist here for sign-off."
        />
      ) : (
        <>
          <ul className="scroll-thin max-h-72 divide-y divide-line overflow-y-auto">
            {pending.map((p) => {
              const checked = sel.has(p.fingerprint);
              return (
                <li key={p.fingerprint}>
                  <label className="flex cursor-pointer items-start gap-2.5 px-4 py-2.5 transition hover:bg-card2">
                    <input type="checkbox" checked={checked} onChange={() => toggle(p.fingerprint)} className="mt-0.5 h-4 w-4 accent-brand" />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-card2 px-1.5 py-0.5 font-mono text-[10px] text-muted">{p.tool_name || "tool"}</span>
                        {p.deferred_at && <span className="text-[11px] text-muted">{relTime(p.deferred_at)}</span>}
                      </div>
                      <code className="mt-1 block break-all font-mono text-xs text-fg">{p.command || p.summary || p.fingerprint}</code>
                    </div>
                  </label>
                </li>
              );
            })}
          </ul>

          <div className="flex flex-wrap items-center gap-2 border-t border-line p-3">
            <button
              onClick={() => void approveSelected()}
              disabled={busy || sel.size === 0}
              className={cx(
                "inline-flex h-9 items-center gap-1.5 rounded-lg border border-line bg-card px-3 text-sm font-medium transition hover:border-brand/40",
                (busy || sel.size === 0) && "cursor-not-allowed opacity-60",
              )}
            >
              <Check size={14} /> Approve selected{sel.size ? ` (${sel.size})` : ""}
            </button>
            <button
              onClick={() => void doResume()}
              disabled={busy || running}
              title={running ? "A run is already in progress" : "Re-run; approved commands execute, new ones defer again"}
              className={cx(
                "ml-auto inline-flex h-9 items-center gap-1.5 rounded-lg bg-brand px-4 text-sm font-medium text-brand-fg transition hover:brightness-110",
                (busy || running) && "cursor-not-allowed opacity-60",
              )}
            >
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />} Resume run
            </button>
          </div>
        </>
      )}
    </Card>
  );
}
