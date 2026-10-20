"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import {
  Search, CornerDownLeft, LayoutDashboard, Target, Bug, Workflow, Network,
  Activity, Bot, FileText, Settings2, Moon, RotateCcw,
} from "lucide-react";
import { useConsole } from "@/lib/store";
import { sevMeta } from "@/lib/theme";
import { cx } from "@/lib/format";

interface Cmd { id: string; group: string; label: string; hint?: string; icon: React.ReactNode; keywords?: string; run: () => void; }

const PAGES = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/engagements", label: "Engagements", icon: Target },
  { href: "/findings", label: "Findings", icon: Bug },
  { href: "/chains", label: "Attack chains", icon: Workflow },
  { href: "/assets", label: "Assets & scope", icon: Network },
  { href: "/activity", label: "Activity", icon: Activity },
  { href: "/agents", label: "Agents", icon: Bot },
  { href: "/report", label: "Report", icon: FileText },
  { href: "/settings", label: "Settings", icon: Settings2 },
];

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const router = useRouter();
  const { resolvedTheme, setTheme } = useTheme();
  const { engagements, findings, activeId, setActiveId, openFinding, clearData, mode } = useConsole();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) { setQ(""); setSel(0); const t = setTimeout(() => inputRef.current?.focus(), 20); return () => clearTimeout(t); }
  }, [open]);

  const cmds = useMemo<Cmd[]>(() => {
    const list: Cmd[] = [];
    PAGES.forEach((p) => list.push({ id: "go:" + p.href, group: "Go to", label: p.label, icon: <p.icon size={15} />, run: () => { router.push(p.href); onClose(); } }));
    engagements.forEach((e) => list.push({
      id: "eng:" + e.id, group: "Switch engagement", label: e.name, hint: e.id === activeId ? "active" : e.target, keywords: e.target,
      icon: <Target size={15} />, run: () => { setActiveId(e.id); router.push("/"); onClose(); },
    }));
    findings.filter((f) => !f.composite).forEach((f) => list.push({
      id: "find:" + f.id, group: "Findings", label: `${f.id} · ${f.title}`, hint: f.severity, keywords: `${f.asset} ${f.category?.cwe ?? ""}`,
      icon: <span className="h-2 w-2 rounded-full" style={{ background: sevMeta(f.severity).color }} />, run: () => { openFinding(f); onClose(); },
    }));
    list.push({ id: "act:theme", group: "Actions", label: `Switch to ${resolvedTheme === "dark" ? "light" : "dark"} theme`, icon: <Moon size={15} />, run: () => { setTheme(resolvedTheme === "dark" ? "light" : "dark"); onClose(); } });
    if (mode === "live") list.push({ id: "act:clear", group: "Actions", label: "Clear loaded data", icon: <RotateCcw size={15} />, run: () => { clearData(); onClose(); } });
    return list;
  }, [engagements, findings, activeId, resolvedTheme, mode, router, setActiveId, openFinding, setTheme, clearData, onClose]);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return cmds.filter((c) => c.group !== "Findings"); // keep the long findings list hidden until searched
    return cmds.filter((c) => (c.label + " " + (c.keywords ?? "") + " " + c.group).toLowerCase().includes(s));
  }, [q, cmds]);

  useEffect(() => { if (sel >= filtered.length) setSel(0); }, [filtered.length, sel]);
  useEffect(() => { listRef.current?.querySelector('[data-sel="true"]')?.scrollIntoView({ block: "nearest" }); }, [sel]);

  if (!open) return null;

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, filtered.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); filtered[sel]?.run(); }
    else if (e.key === "Escape") { e.preventDefault(); onClose(); }
  };

  let lastGroup = "";
  return (
    <div className="fixed inset-0 z-[70] flex items-start justify-center bg-black/50 p-4 pt-[12vh] backdrop-blur-sm animate-fade-in" onClick={onClose}>
      <div className="w-full max-w-xl overflow-hidden rounded-xl border border-line bg-card shadow-pop" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 border-b border-line px-3">
          <Search size={16} className="text-muted" />
          <input
            ref={inputRef} value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey}
            placeholder="Search views, engagements, findings…"
            className="h-12 flex-1 bg-transparent text-sm outline-none placeholder:text-muted"
          />
          <kbd className="rounded border border-line bg-card2 px-1.5 py-0.5 text-[10px] text-muted">ESC</kbd>
        </div>
        <div ref={listRef} className="scroll-thin max-h-[52vh] overflow-y-auto p-1.5">
          {filtered.length === 0 && <div className="px-3 py-8 text-center text-sm text-muted">No matches.</div>}
          {filtered.map((c, i) => {
            const showGroup = c.group !== lastGroup;
            lastGroup = c.group;
            return (
              <div key={c.id}>
                {showGroup && <div className="px-2 pb-1 pt-2 text-[10px] font-medium uppercase tracking-wider text-muted">{c.group}</div>}
                <button
                  data-sel={i === sel}
                  onMouseEnter={() => setSel(i)}
                  onClick={() => c.run()}
                  className={cx("flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-sm transition", i === sel ? "bg-fg/[0.07]" : "")}
                >
                  <span className="grid h-5 w-5 place-items-center text-muted">{c.icon}</span>
                  <span className="min-w-0 flex-1 truncate">{c.label}</span>
                  {c.hint && <span className="shrink-0 text-[11px] capitalize text-muted">{c.hint}</span>}
                  {i === sel && <CornerDownLeft size={13} className="shrink-0 text-muted" />}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
