"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Check, ChevronsUpDown } from "lucide-react";
import { cx } from "@/lib/format";
import { useConsole } from "@/lib/store";
import { ENGAGEMENT_STATUS } from "@/lib/theme";
import { Dot } from "@/components/ui/primitives";

/**
 * Bottom-left engagement switcher. The trigger shows the active engagement
 * (avatar · name · status); clicking opens an upward popover listing every
 * engagement so the user can switch the active one in place — `setActiveId`
 * persists the choice (localStorage) and lazy-loads that engagement's dataset.
 * A "Manage engagements" link preserves the old navigation affordance.
 */
export function EngagementSwitcher({ onNavigate }: { onNavigate?: () => void }) {
  const { engagements, activeEngagement, activeId, setActiveId } = useConsole();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const st = ENGAGEMENT_STATUS[activeEngagement.status];

  // close on outside-click / Escape
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const choose = (id: string) => {
    if (id !== activeId) setActiveId(id);
    setOpen(false);
  };

  return (
    <div ref={ref} className="relative border-t border-line p-3">
      {open && (
        <div
          role="listbox"
          className="absolute bottom-full left-3 right-3 mb-2 overflow-hidden rounded-xl border border-line bg-card shadow-lg"
        >
          <div className="scroll-thin max-h-72 overflow-y-auto p-1">
            {engagements.map((e) => {
              const es = ENGAGEMENT_STATUS[e.status];
              const active = e.id === activeId;
              return (
                <button
                  key={e.id}
                  role="option"
                  aria-selected={active}
                  onClick={() => choose(e.id)}
                  className={cx(
                    "flex w-full items-center gap-2.5 rounded-lg px-2 py-2 text-left transition",
                    active ? "bg-brand/10" : "hover:bg-card2",
                  )}
                >
                  <Dot color={es.color} pulse={e.status === "running"} />
                  <div className="min-w-0 flex-1">
                    <div className={cx("truncate text-xs font-medium", active ? "text-brand" : "text-fg")}>
                      {e.name}
                    </div>
                    <div className="truncate text-[11px] text-muted">{e.target}</div>
                  </div>
                  {active && <Check size={14} className="shrink-0 text-brand" />}
                </button>
              );
            })}
          </div>
          <Link
            href="/engagements"
            onClick={() => { setOpen(false); onNavigate?.(); }}
            className="block border-t border-line px-3 py-2 text-[11px] font-medium text-muted transition hover:bg-card2 hover:text-fg"
          >
            Manage engagements →
          </Link>
        </div>
      )}

      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-haspopup="listbox"
        aria-expanded={open}
        className="flex w-full items-center gap-2.5 rounded-lg p-2 text-left transition hover:bg-card2"
      >
        <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-card2 text-xs font-semibold">
          {(activeEngagement.name || "?").slice(0, 1).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <div className="truncate text-xs font-medium">{activeEngagement.name}</div>
          <div className="flex items-center gap-1.5 text-[11px] text-muted">
            <Dot color={st.color} pulse={activeEngagement.status === "running"} />
            {st.label}
          </div>
        </div>
        <ChevronsUpDown size={14} className="shrink-0 text-muted" />
      </button>
    </div>
  );
}
