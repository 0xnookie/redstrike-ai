"use client";

import { useCallback, useState } from "react";
import { Upload } from "lucide-react";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";
import { useConsole } from "@/lib/store";
import { cx } from "@/lib/format";

export function AppShell({ children }: { children: React.ReactNode }) {
  const { loadFiles } = useConsole();
  const [desktopOpen, setDesktopOpen] = useState(true);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [dragging, setDragging] = useState(false);

  const toggle = useCallback(() => {
    if (typeof window !== "undefined" && window.matchMedia("(min-width:1024px)").matches) {
      setDesktopOpen((v) => !v);
    } else {
      setMobileOpen((v) => !v);
    }
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
      {/* desktop sidebar (in flow) */}
      <Sidebar className={cx("hidden h-screen sticky top-0", desktopOpen && "lg:flex")} />

      {/* mobile drawer */}
      {mobileOpen && (
        <>
          <div className="fixed inset-0 z-40 bg-black/50 lg:hidden" onClick={() => setMobileOpen(false)} />
          <Sidebar className="fixed inset-y-0 left-0 z-50 flex animate-slide-in lg:hidden" onNavigate={() => setMobileOpen(false)} />
        </>
      )}

      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar onToggleSidebar={toggle} />
        <main className="scroll-thin flex-1 overflow-x-hidden px-4 py-6 sm:px-6">
          <div className="mx-auto max-w-7xl animate-fade-in">{children}</div>
        </main>
      </div>

      {dragging && (
        <div className="pointer-events-none fixed inset-0 z-[60] flex items-center justify-center bg-brand/10 backdrop-blur-sm">
          <div className="flex flex-col items-center gap-2 rounded-2xl border-2 border-dashed border-brand bg-card px-10 py-8 shadow-pop">
            <Upload className="text-brand" size={28} />
            <p className="text-sm font-medium">Drop findings_consolidated.json, scope.json or attack_chains.json</p>
            <p className="text-xs text-muted">Files are routed by shape — any combination works</p>
          </div>
        </div>
      )}
    </div>
  );
}
