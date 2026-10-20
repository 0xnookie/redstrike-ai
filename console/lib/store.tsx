"use client";

import { createContext, useCallback, useContext, useMemo, useState } from "react";
import type { ConsoleData, Engagement, Finding, AttackChain } from "./types";
import { sampleData } from "./data";

type Mode = "demo" | "live";

interface ConsoleCtx {
  mode: Mode;
  engagements: Engagement[];
  activeEngagement: Engagement;
  activeId: string;
  setActiveId: (id: string) => void;
  /** findings / chains scoped to the active engagement */
  findings: Finding[];
  chains: AttackChain[];
  agents: ConsoleData["agents"];
  activity: ConsoleData["activity"];
  assets: ConsoleData["assets"];
  loadFiles: (files: FileList | File[]) => Promise<string[]>;
  resetDemo: () => void;
  /** finding detail drawer, lifted to the app so it opens from any view (and the ⌘K palette) */
  selectedFinding: Finding | null;
  openFinding: (f: Finding) => void;
  closeFinding: () => void;
}

const Ctx = createContext<ConsoleCtx | null>(null);

export function ConsoleProvider({ children }: { children: React.ReactNode }) {
  const [data, setData] = useState<ConsoleData>(sampleData);
  const [mode, setMode] = useState<Mode>("demo");
  const [activeId, setActiveId] = useState<string>(sampleData.activeEngagementId);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const openFinding = useCallback((f: Finding) => setSelectedFinding(f), []);
  const closeFinding = useCallback(() => setSelectedFinding(null), []);

  const activeEngagement =
    data.engagements.find((e) => e.id === activeId) ?? data.engagements[0];

  // findings / chains scoped to the active engagement; findings without an
  // engagement_id are treated as belonging to the active one (loaded files).
  const findings = useMemo(
    () => data.findings.filter((f) => !f.engagement_id || f.engagement_id === activeId),
    [data.findings, activeId]
  );
  const chains = data.chains;

  const classify = useCallback(
    (json: unknown, name: string): string => {
      // findings array
      if (Array.isArray(json)) {
        const tagged = (json as Finding[]).map((f) => ({ ...f, engagement_id: activeId }));
        setData((d) => ({ ...d, findings: tagged }));
        setMode("live");
        return "findings";
      }
      if (json && typeof json === "object") {
        const o = json as Record<string, unknown>;
        if (Array.isArray(o.chains)) {
          setData((d) => ({ ...d, chains: o.chains as AttackChain[] }));
          return "chains";
        }
        if (Array.isArray(o.findings)) {
          const tagged = (o.findings as Finding[]).map((f) => ({ ...f, engagement_id: activeId }));
          setData((d) => ({ ...d, findings: tagged }));
          setMode("live");
          return "findings";
        }
        if (o.in_scope || o.window || o.engagement) {
          // scope.json → patch the active engagement's header fields
          setData((d) => ({
            ...d,
            engagements: d.engagements.map((e) =>
              e.id === activeId
                ? {
                    ...e,
                    name: (o.engagement as string) || e.name,
                    authorized_by: (o.authorized_by as string) || e.authorized_by,
                    window: (o.window as Engagement["window"]) || e.window,
                    in_scope: (o.in_scope as Engagement["in_scope"]) || e.in_scope,
                    out_of_scope: (o.out_of_scope as Engagement["out_of_scope"]) || e.out_of_scope,
                    rules: (o.rules as Engagement["rules"]) || e.rules,
                  }
                : e
            ),
          }));
          return "scope";
        }
      }
      return "unknown";
    },
    [activeId]
  );

  const loadFiles = useCallback(
    async (files: FileList | File[]): Promise<string[]> => {
      const arr = Array.from(files);
      const kinds: string[] = [];
      for (const file of arr) {
        try {
          const text = await file.text();
          kinds.push(classify(JSON.parse(text), file.name));
        } catch (e) {
          kinds.push(`error:${file.name}`);
        }
      }
      return kinds;
    },
    [classify]
  );

  const resetDemo = useCallback(() => {
    setData(sampleData);
    setActiveId(sampleData.activeEngagementId);
    setMode("demo");
  }, []);

  const value: ConsoleCtx = {
    mode,
    engagements: data.engagements,
    activeEngagement,
    activeId,
    setActiveId,
    findings,
    chains,
    agents: data.agents,
    activity: data.activity,
    assets: data.assets,
    loadFiles,
    resetDemo,
    selectedFinding,
    openFinding,
    closeFinding,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useConsole(): ConsoleCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useConsole must be used within ConsoleProvider");
  return ctx;
}
