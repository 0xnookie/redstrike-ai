"use client";

import { useEffect } from "react";
import { X, Rocket } from "lucide-react";
import { LaunchPanel } from "./LaunchPanel";

/**
 * Slide-over launch flow — the "Start an engagement" drawer, opened from the
 * Engagements view. Wraps the guided create+launch form; closes on success.
 */
export function LaunchDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm animate-fade-in" onClick={onClose} />
      <aside className="scroll-thin drawer-edge fixed inset-y-0 right-0 z-50 w-full max-w-lg animate-slide-in overflow-y-auto border-l border-line bg-card p-5">
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <div className="font-mono text-xs tracking-wide text-faint">New engagement</div>
            <h2 className="mt-1 flex items-center gap-2 text-lg font-semibold leading-tight text-fg-strong">
              <Rocket size={17} className="text-brand" /> Start an engagement
            </h2>
          </div>
          <button
            onClick={onClose}
            aria-label="Close"
            className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line text-muted transition hover:text-fg"
          >
            <X size={16} />
          </button>
        </div>
        <LaunchPanel bare onLaunched={onClose} />
      </aside>
    </>
  );
}
