"use client";

import { useEffect } from "react";
import { ThemeProvider } from "next-themes";
import { ConsoleProvider, useConsole } from "@/lib/store";
import { ControlProvider, useControl } from "@/components/control/ControlProvider";
import { ToastProvider } from "@/components/ui/Toast";

/** Tells the data store which engagements have a live run (from the control plane), so it
 *  can live-refresh the one being viewed. A key string, so the store only re-renders when the
 *  set of live runs actually changes — not on every control-plane update. */
function LiveRunBridge() {
  const { runs } = useControl();
  const { setLiveRunIds } = useConsole();
  const key = Object.keys(runs).sort().join("|");
  useEffect(() => setLiveRunIds(key), [key, setLiveRunIds]);
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
