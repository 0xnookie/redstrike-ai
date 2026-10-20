"use client";

import { useRef } from "react";
import { PanelLeft, Search, Upload, RotateCcw } from "lucide-react";
import { useConsole } from "@/lib/store";
import { ThemeToggle } from "./ThemeToggle";
import { cx } from "@/lib/format";

export function Topbar({ onToggleSidebar, onOpenPalette }: { onToggleSidebar: () => void; onOpenPalette: () => void }) {
  const { mode, loadFiles, clearData } = useConsole();
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

      <div className="hidden flex-1 sm:flex">
        <button
          onClick={onOpenPalette}
          className="flex h-9 w-full max-w-md items-center gap-2 rounded-lg border border-line bg-card px-3 text-sm text-muted transition hover:border-fg/30"
        >
          <Search size={15} />
          <span className="flex-1 text-left">Search findings, assets, agents…</span>
          <kbd className="rounded border border-line bg-card2 px-1.5 py-0.5 text-[10px]">⌘K</kbd>
        </button>
      </div>
      <div className="flex-1 sm:hidden" />
      <button
        onClick={onOpenPalette}
        aria-label="Open search"
        className="grid h-9 w-9 place-items-center rounded-lg text-muted transition hover:bg-card2 hover:text-fg sm:hidden"
      >
        <Search size={18} />
      </button>

      <span
        className="hidden items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium sm:inline-flex"
        style={{
          color: mode === "empty" ? "#9ca3af" : "#22c55e",
          background: (mode === "empty" ? "#9ca3af" : "#22c55e") + "1f",
          border: `1px solid ${(mode === "empty" ? "#9ca3af" : "#22c55e") + "55"}`,
        }}
      >
        <span className="h-1.5 w-1.5 rounded-full" style={{ background: mode === "empty" ? "#9ca3af" : "#22c55e" }} />
        {mode === "empty" ? "No data loaded" : "Live engagement"}
      </span>

      {mode === "live" && (
        <button
          onClick={clearData}
          title="Clear loaded data"
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
