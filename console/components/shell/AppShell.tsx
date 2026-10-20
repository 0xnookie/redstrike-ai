"use client";

import { useCallback, useEffect, useState } from "react";
import { Upload } from "lucide-react";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { StatusBar } from "./StatusBar";
import { CommandPalette } from "./CommandPalette";
import { FindingDrawer } from "@/components/findings/FindingDrawer";
import { useConsole } from "@/lib/store";

export function AppShell({ children }: { children: React.ReactNode }) {
  const { loadFiles, selectedFinding, closeFinding } = useConsole();
  const [desktopOpen, setDesktopOpen] = useState(true);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);

  const toggle = useCallback(() => {
    if (typeof window !== "undefined" && window.matchMedia("(min-width:1024px)").matches) setDesktopOpen((v) => !v);
    else setMobileOpen((v) => !v);
  }, []);

  // ⌘K / Ctrl+K opens the command palette
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPaletteOpen((o) => !o); }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      if (e.dataTransfer?.files?.length) loadFiles(e.dataTransfer.files);
    },
    [loadFiles]
  );

  return (
    <div
      className="flex min-h-screen"
      onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={(e) => { if (e.currentTarget === e.target) setDragging(false); }}
      onDrop={onDrop}
    >
      <Sidebar className={desktopOpen ? "hidden h-screen sticky top-0 lg:flex" : "hidden"} />

      {mobileOpen && (
        <>
          <div className="fixed inset-0 z-40 bg-black/50 lg:hidden" onClick={() => setMobileOpen(false)} />
          <Sidebar className="fixed inset-y-0 left-0 z-50 flex animate-slide-in lg:hidden" onNavigate={() => setMobileOpen(false)} />
        </>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onToggleSidebar={toggle} onOpenPalette={() => setPaletteOpen(true)} />
        <main className="scroll-thin flex-1 overflow-x-hidden px-4 py-6 sm:px-6">
          <div className="mx-auto max-w-7xl animate-fade-in">{children}</div>
        </main>
        <StatusBar />
      </div>

      {dragging && (
        <div className="pointer-events-none fixed inset-0 z-[60] flex items-center justify-center bg-black/40 backdrop-blur-sm">
          <div className="flex flex-col items-center gap-2 rounded-2xl border-2 border-dashed border-fg/40 bg-card px-10 py-8 shadow-pop">
            <Upload className="text-fg" size={28} />
            <p className="text-sm font-medium">Drop findings_consolidated.json, scope.json or attack_chains.json</p>
            <p className="text-xs text-muted">Files are routed by shape — any combination works</p>
          </div>
        </div>
      )}

      <FindingDrawer finding={selectedFinding} onClose={closeFinding} />
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  );
}
