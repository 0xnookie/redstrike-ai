"use client";

// Route-segment error boundary. Because it mounts inside app/layout.tsx (which renders the
// AppShell), a render throw in any page degrades to THIS recoverable card WITHOUT losing the
// nav/sidebar — it replaces only the `children` slot, not the shell. This is what kills the
// full-blank failure mode (the cve-intel incident): previously an unguarded enum map or a
// malformed field would unmount the whole route subtree to an empty screen.

import { useEffect } from "react";
import { AlertTriangle, RotateCcw } from "lucide-react";

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    if (typeof console !== "undefined") console.error("[console] route error boundary:", error);
  }, [error]);

  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-3 px-6 text-center">
      <div className="grid h-12 w-12 place-items-center rounded-full border border-amber-500/40 bg-amber-500/10 text-amber-500">
        <AlertTriangle size={22} />
      </div>
      <h1 className="text-lg font-semibold text-fg-strong">This view hit a malformed data field</h1>
      <p className="max-w-md text-sm text-muted">
        A value in the loaded engagement data wasn&apos;t in the shape this view expected, so rendering stopped here. The
        navigation and your other views are unaffected — retry to re-render, or switch engagements.
      </p>
      {error?.digest && <p className="font-mono text-[11px] text-faint">ref {error.digest}</p>}
      <button
        onClick={reset}
        className="mt-1 inline-flex items-center gap-1.5 rounded-full bg-brand px-4 py-2 text-sm font-medium text-brand-fg transition hover:brightness-110"
      >
        <RotateCcw size={14} /> Retry this view
      </button>
    </div>
  );
}
