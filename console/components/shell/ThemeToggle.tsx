"use client";

import { useEffect, useState } from "react";
import { useTheme } from "next-themes";
import { Moon, Sun } from "lucide-react";

export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const isDark = resolvedTheme === "dark";
  return (
    <button
      aria-label="Toggle theme"
      title={isDark ? "Switch to light" : "Switch to dark"}
      onClick={() => setTheme(isDark ? "light" : "dark")}
      className="grid h-9 w-9 place-items-center rounded-lg border border-line bg-card text-muted transition hover:text-fg"
    >
      {/* render a stable icon until mounted to avoid hydration mismatch */}
      {!mounted ? <Sun size={16} /> : isDark ? <Sun size={16} /> : <Moon size={16} />}
    </button>
  );
}
