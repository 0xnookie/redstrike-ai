"use client";

import { useRef } from "react";
import { PanelLeft, Search, Upload, RotateCcw } from "lucide-react";
import { useConsole } from "@/lib/store";
import { ThemeToggle } from "./ThemeToggle";
import { cx } from "@/lib/format";

export function Topbar({ onToggleSidebar }: { onToggleSidebar: () => void }) {
  const { mode, loadFiles, resetDemo } = useConsole();
  const fileRef = useRef<HTMLInputElement>(null);

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b border-line bg-bg/80 px-3 backdrop-blur sm:px-4">
      <button
        onClick={onToggleSidebar}
        aria-label="Toggle sidebar"
        className="grid h-9 w-9 place-items-center rounded-lg text-muted transition hover:bg-card2 hover:text-fg"
      >
        <PanelLeft size={18} />
      </button>

      <div className="relative hidden flex-1 sm:block">
        <Search size={15} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
        <input
          placeholder="Search findings, assets, agents…"
          className="h-9 w-full max-w-md rounded-lg border border-line bg-card pl-9 pr-16 text-sm outline-none placeholder:text-muted focus:border-brand/50 focus:ring-2 focus:ring-brand/20"
        />
        <kbd className="pointer-events-none absolute left-[22rem] top-1/2 hidden -translate-y-1/2 rounded border border-line bg-card2 px-1.5 py-0.5 text-[10px] text-muted lg:block">
          ⌘K
        </kbd>
      </div>
      <div className="flex-1 sm:hidden" />

      <span
        className="hidden items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium sm:inline-flex"
        style={{
          color: mode === "demo" ? "#f59e0b" : "#22c55e",
          background: (mode === "demo" ? "#f59e0b" : "#22c55e") + "1f",
          border: `1px solid ${(mode === "demo" ? "#f59e0b" : "#22c55e") + "55"}`,
        }}
      >
        <span className="h-1.5 w-1.5 rounded-full" style={{ background: mode === "demo" ? "#f59e0b" : "#22c55e" }} />
        {mode === "demo" ? "Demo data" : "Live engagement"}
      </span>

      {mode === "live" && (
        <button
          onClick={resetDemo}
          title="Reset to demo data"
          className="grid h-9 w-9 place-items-center rounded-lg border border-line bg-card text-muted transition hover:text-fg"
        >
          <RotateCcw size={15} />
        </button>
      )}

      <button
        onClick={() => fileRef.current?.click()}
        className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-brand px-3 text-sm font-medium text-brand-fg transition hover:brightness-110"
      >
        <Upload size={15} />
        <span className="hidden sm:inline">Load data</span>
      </button>
      <input
        ref={fileRef}
        type="file"
        accept=".json,application/json"
        multiple
        className="hidden"
        onChange={(e) => e.target.files && loadFiles(e.target.files)}
      />

      <ThemeToggle />
      <div className="grid h-9 w-9 place-items-center rounded-full bg-card2 text-sm font-semibold">H</div>
    </header>
  );
}
