"use client";

import { ThemeProvider } from "next-themes";
import { ConsoleProvider } from "@/lib/store";
import { ControlProvider } from "@/components/control/ControlProvider";

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <ThemeProvider attribute="class" defaultTheme="dark" enableSystem disableTransitionOnChange>
      <ConsoleProvider>
        <ControlProvider>{children}</ControlProvider>
      </ConsoleProvider>
    </ThemeProvider>
  );
}
