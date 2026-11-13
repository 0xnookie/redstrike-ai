"use client";

import { ThemeProvider } from "next-themes";
import { ConsoleProvider } from "@/lib/store";
import { ControlProvider } from "@/components/control/ControlProvider";
import { ToastProvider } from "@/components/ui/Toast";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem disableTransitionOnChange>
      <ToastProvider>
        <ConsoleProvider>
          <ControlProvider>{children}</ControlProvider>
        </ConsoleProvider>
      </ToastProvider>
    </ThemeProvider>
  );
}
