"use client";

import { useEffect, useRef, useState } from "react";
import { Radio, Terminal, Eraser, ArrowRight, CircleCheck, CircleAlert, Cpu, ChevronRight, ChevronDown } from "lucide-react";
import { useControl } from "./ControlProvider";
import type { RunEvent } from "@/lib/control";
import { Card } from "@/components/ui/primitives";
import { cx } from "@/lib/format";

const toneClass: Record<string, string> = {
  ok: "text-emerald-400",
  warn: "text-amber-400",
  cyan: "text-cyan-400",
  muted: "text-muted",
};

function EventIcon({ kind }: { kind: RunEvent["kind"] }) {
  if (kind === "tool") return <ArrowRight size={13} className="mt-0.5 shrink-0 text-cyan-400" />;
  if (kind === "system") return <Cpu size={13} className="mt-0.5 shrink-0 text-cyan-400" />;
  if (kind === "result") return <CircleCheck size={13} className="mt-0.5 shrink-0" />;
  if (kind === "error") return <CircleAlert size={13} className="mt-0.5 shrink-0 text-amber-400" />;
  return <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-muted/50" />;
}

export function RunStream() {
  const { events, running, clearEvents, auth } = useControl();
  const [open, setOpen] = useState(false); // raw log is secondary to the orchestration view
  // a run is only actually billed per-token when Claude is connected via a raw API key;
  // a login/OAuth connection is subscription usage, so total_cost_usd is notional there.
  const billed = auth?.providers?.claude?.via === "api_key";
  const scrollRef = useRef<HTMLDivElement>(null);
  const atBottom = useRef(true);

  // autoscroll only while the user is already pinned to the bottom
  useEffect(() => {
    const el = scrollRef.current;
    if (open && el && atBottom.current) el.scrollTop = el.scrollHeight;
  }, [events, open]);

  const onScroll = () => {
    const el = scrollRef.current;
    if (el) atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };

  return (
    <Card className={cx("flex flex-col", open && "min-h-[18rem]")}>
      <div className="flex items-center justify-between px-4 py-2.5">
        <button onClick={() => setOpen((v) => !v)} className="flex items-center gap-2 text-sm font-semibold">
          {open ? <ChevronDown size={14} className="text-muted" /> : <ChevronRight size={14} className="text-muted" />}
          <Terminal size={15} className="text-brand" /> Raw engine log
          {running ? (
            // pid-driven: stays on between loop invocations (a `result` is not run-over)
            <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-400">
              <Radio size={12} className="animate-pulse" /> streaming
            </span>
          ) : events.length > 0 ? (
            // the run's process has exited — the authoritative "ended" signal
            <span className="inline-flex items-center gap-1 text-[11px] font-medium text-muted">
              <CircleCheck size={12} /> run ended
            </span>
          ) : null}
          {!open && events.length > 0 && <span className="text-[11px] font-normal text-muted">· {events.length} events</span>}
        </button>
        {open && events.length > 0 && (
          <button onClick={clearEvents} className="inline-flex items-center gap-1 text-xs text-muted transition hover:text-fg">
            <Eraser size={12} /> Clear
          </button>
        )}
      </div>

      {open && (
      <div ref={scrollRef} onScroll={onScroll} className="scroll-thin flex-1 overflow-y-auto border-t border-line p-3 font-mono text-xs leading-relaxed">
        {events.length === 0 ? (
          <div className="flex h-full min-h-[12rem] flex-col items-center justify-center gap-1 text-center text-muted">
            <Terminal size={22} className="opacity-50" />
            <p className="text-sm">No run events yet.</p>
            <p className="max-w-xs text-xs">
              Launch an autonomous run — the engine&apos;s tool calls stream here from the engagement&apos;s audit log.
            </p>
          </div>
        ) : (
          <ul className="space-y-0.5">
            {events.map((ev) => (
              <li key={ev.key} className={cx("flex items-start gap-2", ev.kind === "run" && "mt-2 border-t border-line pt-2")}>
                <EventIcon kind={ev.kind} />
                <div className="min-w-0 flex-1">
                  <div className={cx("flex flex-wrap items-baseline gap-x-2", toneClass[ev.tone ?? "muted"])}>
                    <span className={cx(ev.kind === "tool" && "text-fg")}>{ev.text}</span>
                    {ev.detail && <span className="truncate text-muted">{ev.detail}</span>}
                    {ev.kind === "result" && ev.costUsd != null && (
                      <span
                        className="text-muted"
                        title={
                          billed
                            ? "Actual per-token cost (Claude connected via API key)."
                            : "List-price API-equivalent — not billed on your subscription; this usage counts against your plan limits."
                        }
                      >
                        {billed ? `· $${ev.costUsd.toFixed(4)}` : `· ~$${ev.costUsd.toFixed(2)} est · plan usage`}
                      </span>
                    )}
                  </div>
                  {ev.kind === "result" && !!ev.deferred && (
                    <div className="mt-1 inline-flex items-center gap-1 text-[11px] text-amber-400">
                      <CircleAlert size={12} /> {ev.deferred} action{ev.deferred === 1 ? "" : "s"} deferred — approve below, then resume.
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
      )}
    </Card>
  );
}
