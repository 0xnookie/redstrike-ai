"use client";

import { useEffect, useRef, useState } from "react";
import { useTheme } from "next-themes";
import { Sun, Moon, Monitor, Upload, RotateCcw } from "lucide-react";
import { useConsole } from "@/lib/store";
import { cx } from "@/lib/format";
import { Card, PageHeader } from "@/components/ui/primitives";

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();
  const { mode, clearData, loadFiles } = useConsole();
  const [mounted, setMounted] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  useEffect(() => setMounted(true), []);

  const themes = [
    { value: "light", label: "Light", icon: Sun },
    { value: "dark", label: "Dark", icon: Moon },
    { value: "system", label: "System", icon: Monitor },
  ];

  return (
    <>
      <PageHeader title="Settings" subtitle="Appearance, data source and engagement rules." />

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {/* appearance */}
        <Card className="p-5">
          <h2 className="text-sm font-semibold">Appearance</h2>
          <p className="mb-3 text-xs text-muted">Choose the console theme. System follows your OS.</p>
          <div className="grid grid-cols-3 gap-2">
            {themes.map((t) => {
              const Icon = t.icon;
              const active = mounted && theme === t.value;
              return (
                <button
                  key={t.value}
                  onClick={() => setTheme(t.value)}
                  className={cx(
                    "flex flex-col items-center gap-2 rounded-xl border p-4 text-sm transition",
                    active ? "border-brand/60 bg-brand/10 text-brand" : "border-line text-muted hover:text-fg"
                  )}
                >
                  <Icon size={20} />
                  {t.label}
                </button>
              );
            })}
          </div>
        </Card>

        {/* data source */}
        <Card className="p-5">
          <h2 className="text-sm font-semibold">Data source</h2>
          <p className="mb-3 text-xs text-muted">
            The console reads the engagement JSON the Redstrike skills emit — usually via
            <code className="mx-1 rounded bg-card2 px-1 py-0.5 text-[11px]">python scripts/console.py engagements/&lt;dir&gt;</code>.
            You can also load files here: a
            <code className="mx-1 rounded bg-card2 px-1 py-0.5 text-[11px]">findings_consolidated.json</code>,
            <code className="mx-1 rounded bg-card2 px-1 py-0.5 text-[11px]">host_discovery.json</code>,
            <code className="mx-1 rounded bg-card2 px-1 py-0.5 text-[11px]">chains.json</code> or
            <code className="mx-1 rounded bg-card2 px-1 py-0.5 text-[11px]">scope.json</code>.
          </p>
          <div className="flex items-center gap-2">
            <span
              className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium"
              style={{
                color: mode === "empty" ? "#9ca3af" : "#22c55e",
                background: (mode === "empty" ? "#9ca3af" : "#22c55e") + "1f",
                border: `1px solid ${(mode === "empty" ? "#9ca3af" : "#22c55e") + "55"}`,
              }}
            >
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: mode === "empty" ? "#9ca3af" : "#22c55e" }} />
              {mode === "empty" ? "No data loaded" : "Live engagement"}
            </span>
          </div>
          <div className="mt-3 flex items-center gap-2">
            <button onClick={() => fileRef.current?.click()} className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-brand px-3 text-sm font-medium text-brand-fg transition hover:brightness-110">
              <Upload size={15} /> Load JSON
            </button>
            {mode === "live" && (
              <button onClick={clearData} className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-line bg-card px-3 text-sm font-medium transition hover:border-brand/40">
                <RotateCcw size={15} /> Clear data
              </button>
            )}
            <input ref={fileRef} type="file" accept=".json,application/json" multiple className="hidden" onChange={(e) => e.target.files && loadFiles(e.target.files)} />
          </div>
          <p className="mt-3 text-xs text-muted">Files are parsed in the browser and never leave this machine.</p>
        </Card>

        {/* about */}
        <Card className="p-5 lg:col-span-2">
          <h2 className="text-sm font-semibold">About</h2>
          <p className="mt-2 text-sm text-muted">
            Redstrike Console is a frontend-only view over the engagement data model — the same
            findings, attack chains and scope the framework&apos;s skills produce. It computes CVSS 3.1
            base scores in-browser with the same formula as the engagement&apos;s authoritative scorer, and
            keeps composite kill-chains out of the severity counts. Engagement data is sensitive and
            git-ignored; keep it local and deliver through the agreed channel.
          </p>
        </Card>
      </div>
    </>
  );
}
