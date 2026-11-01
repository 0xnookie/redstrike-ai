"use client";

import { useEffect, useRef } from "react";
import { Radio, Terminal, Eraser, ArrowRight, CircleCheck, CircleAlert, Cpu } from "lucide-react";
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
  return <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-muted/50" />;
}

export function RunStream() {
  const { events, running, clearEvents } = useControl();
  const scrollRef = useRef<HTMLDivElement>(null);
  const atBottom = useRef(true);

  // autoscroll only while the user is already pinned to the bottom
  useEffect(() => {
    const el = scrollRef.current;
    if (el && atBottom.current) el.scrollTop = el.scrollHeight;
  }, [events]);

  const onScroll = () => {
    const el = scrollRef.current;
    if (el) atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  };

  return (
    <Card className="flex min-h-[18rem] flex-col">
      <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          <Terminal size={15} className="text-brand" /> Live run
          {running && (
            <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-400">
              <Radio size={12} className="animate-pulse" /> streaming
            </span>
          )}
        </h2>
        {events.length > 0 && (
          <button onClick={clearEvents} className="inline-flex items-center gap-1 text-xs text-muted transition hover:text-fg">
            <Eraser size={12} /> Clear
          </button>
        )}
      </div>

      <div ref={scrollRef} onScroll={onScroll} className="scroll-thin flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed">
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
    </Card>
  );
}
