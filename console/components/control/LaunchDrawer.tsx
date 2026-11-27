"use client";

import { useEffect, useId, useRef } from "react";
import { X, Rocket } from "lucide-react";
import { LaunchPanel } from "./LaunchPanel";

const FOCUSABLE =
  'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

/**
 * Slide-over launch flow — the "Start an engagement" drawer, opened from the
 * Engagements view. Wraps the guided create+launch form; closes on success.
 *
 * Accessibility: a modal dialog — Esc to close, focus moves into the drawer on
 * open, is trapped inside while open, and returns to the trigger on close; the
 * body is scroll-locked underneath.
 */
export function LaunchDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const panelRef = useRef<HTMLElement>(null);
  const titleId = useId();
  // `onClose` is typically a fresh closure each parent render; hold it in a ref so the
  // effect below depends only on `open` and never tears down / re-runs (which would steal
  // focus back to the trigger) just because the parent re-rendered while the drawer is open.
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useEffect(() => {
    if (!open) return;
    const prevActive = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden"; // scroll-lock the page behind the drawer

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onCloseRef.current();
        return;
      }
      if (e.key !== "Tab") return;
      const root = panelRef.current;
      if (!root) return;
      const items = Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (el) => el.offsetParent !== null || el === document.activeElement,
      );
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      // wrap focus at the ends, and pull a stray focus (outside the drawer) back in
      if (e.shiftKey) {
        if (active === first || !root.contains(active)) {
          e.preventDefault();
          last.focus();
        }
      } else if (active === last || !root.contains(active)) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);

    // move focus into the drawer — unless a field already claimed it (autoFocus),
    // in which case leave it there
    const raf = requestAnimationFrame(() => {
      const root = panelRef.current;
      if (root && !root.contains(document.activeElement)) root.focus();
    });

    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
      cancelAnimationFrame(raf);
      prevActive?.focus?.(); // return focus to the element that opened the drawer
    };
  }, [open]);

  if (!open) return null;

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm animate-fade-in" onClick={onClose} />
      <aside
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className="scroll-thin drawer-edge fixed inset-y-0 right-0 z-50 w-full max-w-lg animate-slide-in overflow-y-auto border-l border-line bg-card p-5 outline-none"
      >
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <div className="font-mono text-xs tracking-wide text-faint">New engagement</div>
            <h2 id={titleId} className="mt-1 flex items-center gap-2 text-lg font-semibold leading-tight text-fg-strong">
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
