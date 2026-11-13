"use client";

import { useEffect } from "react";
import { ThemeProvider } from "next-themes";
import { ConsoleProvider, useConsole } from "@/lib/store";
import { ControlProvider, useControl } from "@/components/control/ControlProvider";
import { ToastProvider } from "@/components/ui/Toast";

/** Tells the data store which engagements have a live run and how finished runs ended (from
 *  the control plane), so it can show the true status and live-refresh the one being viewed.
 *  A key string, so the store only re-renders when that run state actually changes — not on
 *  every control-plane update. */
function LiveRunBridge() {
  const { conn, runs, status } = useControl();
  const { setControlRuns } = useConsole();
  // "" = no word from a control plane (offline / read-only viewer): the store falls back to data
  const key = conn === "ready" ? JSON.stringify({ live: Object.keys(runs).sort(), ended: status?.ended ?? {} }) : "";
  useEffect(() => setControlRuns(key), [key, setControlRuns]);
  return null;
}

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem disableTransitionOnChange>
      <ToastProvider>
        <ConsoleProvider>
          <ControlProvider>
            <LiveRunBridge />
            {children}
          </ControlProvider>
        </ConsoleProvider>
      </ToastProvider>
    </ThemeProvider>
  );
}
