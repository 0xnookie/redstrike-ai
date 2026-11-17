"use client";

import { Component, type ReactNode } from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";

/* A reusable render-error boundary for the data-heavy panels. A throw inside a single
 * card (e.g. a malformed row dereferenced in a leaf component) is caught HERE and degrades
 * just that card — the surrounding view, its nav and the other panels keep rendering —
 * instead of unmounting the whole route to a blank screen. This is the belt-and-suspenders
 * companion to the guarded enum accessors in lib/theme.ts: the accessors stop most throws at
 * the source; this catches anything that still slips through a leaf render.
 *
 * Note: a class component is required — componentDidCatch / getDerivedStateFromError have no
 * hook equivalent. React only catches errors thrown while RENDERING the children below this
 * boundary; a throw in the PARENT's own render (e.g. a useMemo above the boundary) is caught
 * by app/error.tsx instead. */

interface Props {
  children: ReactNode;
  /** short label shown in the fallback card (what degraded) */
  label?: string;
  /** optional custom fallback; defaults to the inline card below */
  fallback?: ReactNode;
}
interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error) {
    // surface it to the console (and, later, runtime/error.log) without taking the view down
    if (typeof console !== "undefined") console.error("[console] panel error boundary caught:", error);
  }

  reset = () => this.setState({ error: null });

  render() {
    if (this.state.error) {
      if (this.props.fallback !== undefined) return this.props.fallback;
      return (
        <div className="flex flex-col items-center justify-center gap-2 px-4 py-10 text-center">
          <AlertTriangle size={20} className="text-amber-500" />
          <p className="text-sm font-medium text-fg">{this.props.label ?? "This panel hit a malformed data field"}</p>
          <p className="max-w-sm text-xs text-muted">
            A value in the loaded engagement data wasn&apos;t in the shape this card expected, so it was skipped. The rest
            of the view is unaffected.
          </p>
          <button
            onClick={this.reset}
            className="mt-1 inline-flex items-center gap-1.5 rounded-full border border-line px-3 py-1 text-xs text-fg transition hover:border-fg/30"
          >
            <RotateCcw size={12} /> Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
