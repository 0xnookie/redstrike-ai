"use client";

// Last-resort net for a throw in the ROOT layout itself (above app/error.tsx). Next.js renders
// this in place of the entire document, so it must supply its own <html>/<body>. Styles are
// inline — globals.css/theme tokens may not be applied when the root layout is what failed — so
// this stays legible in any theme. In practice app/error.tsx catches page-level throws; this only
// fires for a failure in the shell/providers above it.

import { useEffect } from "react";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    if (typeof console !== "undefined") console.error("[console] global error boundary:", error);
  }, [error]);

  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#0a0a0b",
          color: "#e5e7eb",
          fontFamily: "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif",
          padding: "24px",
        }}
      >
        <div style={{ maxWidth: 440, textAlign: "center" }}>
          <div style={{ fontSize: 13, letterSpacing: "0.08em", textTransform: "uppercase", color: "#f59e0b" }}>
            Redstrike console
          </div>
          <h1 style={{ margin: "12px 0 8px", fontSize: 20, fontWeight: 600, color: "#f3f4f6" }}>
            The console failed to load
          </h1>
          <p style={{ margin: 0, fontSize: 14, lineHeight: 1.6, color: "#9ca3af" }}>
            An unexpected error broke the application shell. Retry to reload the console; if it persists, reload the page
            or re-serve the engagement data.
          </p>
          {error?.digest && (
            <p style={{ marginTop: 10, fontFamily: "ui-monospace, monospace", fontSize: 11, color: "#6b7280" }}>
              ref {error.digest}
            </p>
          )}
          <button
            onClick={reset}
            style={{
              marginTop: 16,
              cursor: "pointer",
              borderRadius: 9999,
              border: "none",
              background: "#ef4444",
              color: "#fff",
              fontSize: 14,
              fontWeight: 500,
              padding: "8px 18px",
            }}
          >
            Retry
          </button>
        </div>
      </body>
    </html>
  );
}
