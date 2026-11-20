"use client";

import { memo, useCallback, useEffect, useMemo, useReducer, useRef, useState } from "react";
import { Radio, Terminal, Eraser, ArrowRight, CircleCheck, CircleAlert, Cpu, ChevronRight, ChevronDown, CornerDownLeft, ListChecks } from "lucide-react";
import { useControl, useRunStream } from "./ControlProvider";
import type { RunEvent } from "@/lib/control";
import { Card } from "@/components/ui/primitives";
import { cx } from "@/lib/format";

const toneClass: Record<string, string> = {
  ok: "text-emerald-400",
  warn: "text-amber-400",
  cyan: "text-cyan-400",
  muted: "text-muted",
};

// Windowing: only the rows near the viewport are mounted, not the whole (up-to-500) log.
// A source-code audit streams thousands of file-read/grep events in bursts; mounting every
// one as a DOM row and laying the whole list out on each flush is the console's main lag.
const EST_ROW = 22;      // px, first-paint estimate for an un-measured row
const OVERSCAN_PX = 180; // render a little above & below the viewport so a fast scroll stays filled

function EventIcon({ kind, tone }: { kind: RunEvent["kind"]; tone?: RunEvent["tone"] }) {
  if (kind === "dispatch") return <ArrowRight size={13} className="mt-0.5 shrink-0 text-cyan-400" />;
  if (kind === "return") return <CornerDownLeft size={13} className={cx("mt-0.5 shrink-0", tone === "warn" ? "text-amber-400" : "text-emerald-400")} />;
  if (kind === "step") return <ListChecks size={13} className={cx("mt-0.5 shrink-0", tone === "ok" ? "text-emerald-400" : tone === "warn" ? "text-amber-400" : "text-cyan-400")} />;
  if (kind === "tool") return <ChevronRight size={13} className="mt-0.5 shrink-0 text-muted" />;
  if (kind === "system") return <Cpu size={13} className="mt-0.5 shrink-0 text-cyan-400" />;
  if (kind === "result") return <CircleCheck size={13} className="mt-0.5 shrink-0" />;
  if (kind === "error") return <CircleAlert size={13} className="mt-0.5 shrink-0 text-amber-400" />;
  return <span className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-muted/50" />;
}

// Events are immutable once parsed (stable `key`), so a memoized row re-renders only when
// it's new — a flush appending 5 lines renders at most 5 rows, not the whole window. `measure`
// is a stable callback and `billed` a primitive, so neither defeats the memo; a row reports its
// real height once via the `ref` so the windower can place the spacers without clipping wraps.
const EventRow = memo(function EventRow({ ev, billed, measure }: { ev: RunEvent; billed: boolean; measure: (key: string, el: HTMLLIElement | null) => void }) {
  return (
    <li
      ref={(el) => measure(ev.key, el)}
      // spacing is padding (not margin) so the measured offsetHeight is the row's full stride
      className={cx("row-in flex items-start gap-2 pb-0.5", ev.kind === "run" && "mt-2 border-t border-line pt-2")}
    >
      <EventIcon kind={ev.kind} tone={ev.tone} />
      <div className="min-w-0 flex-1">
        <div className={cx("flex flex-wrap items-baseline gap-x-2", toneClass[ev.tone ?? "muted"])}>
          <span className={cx((ev.kind === "tool" || ev.kind === "dispatch") && "text-fg", ev.kind === "dispatch" && "font-medium")}>
            {ev.text}
            {ev.kind === "return" && ev.tone !== "warn" ? " returned" : ""}
          </span>
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
  );
});

export function RunStream() {
  const { running, clearEvents, auth } = useControl();
  const { events } = useRunStream();
  const [open, setOpen] = useState(false); // raw log is secondary to the orchestration view
  // a run is only actually billed per-token when Claude is connected via a raw API key;
  // a login/OAuth connection is subscription usage, so total_cost_usd is notional there.
  const billed = auth?.providers?.claude?.via === "api_key";
  const scrollRef = useRef<HTMLDivElement>(null);
  const atBottom = useRef(true);

  // ---- windowing state: viewport metrics + a per-key measured-height cache ----
  const heights = useRef<Map<string, number>>(new Map());
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(0);
  const [measureTick, bumpMeasure] = useReducer((n: number) => n + 1, 0);
  const scrollRaf = useRef<number | null>(null);
  const measureRaf = useRef<number | null>(null);

  // track the viewport height while the log is open (open toggles its presence; the list also
  // grows/shrinks the card, and the window can be resized)
  useEffect(() => {
    const el = scrollRef.current;
    if (!open || !el || typeof ResizeObserver === "undefined") return;
    const sync = () => setViewportH(el.clientHeight);
    sync();
    const ro = new ResizeObserver(sync);
    ro.observe(el);
    return () => ro.disconnect();
  }, [open]);

  // cache a visible row's real height (handles wrapped text / the deferred badge without
  // clipping); recompute the window once per frame when a height actually changed
  const measure = useCallback((key: string, el: HTMLLIElement | null) => {
    if (!el) return;
    const h = el.offsetHeight;
    if (h && heights.current.get(key) !== h) {
      heights.current.set(key, h);
      if (measureRaf.current == null) {
        measureRaf.current = requestAnimationFrame(() => {
          measureRaf.current = null;
          bumpMeasure();
        });
      }
    }
  }, []);

  // the slice to mount + the spacer heights that stand in for everything off-screen.
  // O(n) over the cap (<=500) — a fraction of a millisecond, only on scroll / resize / measure.
  const win = useMemo(() => {
    void measureTick; // recompute when a visible row reports a new measured height (heights is a ref)
    const H = heights.current;
    const n = events.length;
    const top = scrollTop - OVERSCAN_PX;
    const bottom = scrollTop + viewportH + OVERSCAN_PX;
    let offset = 0;
    let start = 0;
    let end = 0;
    let padTop = 0;
    let startFound = false;
    for (let i = 0; i < n; i++) {
      const h = H.get(events[i].key) ?? EST_ROW;
      if (!startFound && offset + h > top) {
        start = i;
        padTop = offset;
        startFound = true;
      }
      if (offset < bottom) end = i + 1; // last row that begins before the viewport's lower edge
      offset += h;
    }
    const total = offset;
    if (!startFound) {
      // before the first measure (viewportH still 0) show the head; the autoscroll below then
      // pins to the bottom and the RO fills viewportH, so the real slice renders next frame
      start = 0;
      padTop = 0;
      end = Math.min(n, 1);
    }
    if (end < start) end = start;
    let used = padTop;
    for (let i = start; i < end; i++) used += H.get(events[i].key) ?? EST_ROW;
    return { start, end, padTop, padBottom: Math.max(0, total - used) };
  }, [events, scrollTop, viewportH, measureTick]);

  // autoscroll only while the user is already pinned to the bottom (respects scrolling up).
  // Setting scrollTop state too keeps the window aligned with the bottom in the same commit.
  useEffect(() => {
    const el = scrollRef.current;
    if (open && el && atBottom.current) {
      el.scrollTop = el.scrollHeight;
      setScrollTop(el.scrollTop);
    }
  }, [events, open]);

  const onScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    atBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    if (scrollRaf.current == null) {
      scrollRaf.current = requestAnimationFrame(() => {
        scrollRaf.current = null;
        const e2 = scrollRef.current;
        if (e2) setScrollTop(e2.scrollTop);
      });
    }
  };

  useEffect(
    () => () => {
      if (scrollRaf.current != null) cancelAnimationFrame(scrollRaf.current);
      if (measureRaf.current != null) cancelAnimationFrame(measureRaf.current);
    },
    [],
  );

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
          // only the windowed slice is mounted; the spacers reserve the height of everything
          // off-screen so the scrollbar and autoscroll behave as if the full log were present
          <ul style={{ paddingTop: win.padTop, paddingBottom: win.padBottom }}>
            {events.slice(win.start, win.end).map((ev) => (
              <EventRow key={ev.key} ev={ev} billed={billed} measure={measure} />
            ))}
          </ul>
        )}
      </div>
      )}
    </Card>
  );
}
