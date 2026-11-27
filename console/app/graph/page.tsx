"use client";

import { useEffect, useMemo, useState } from "react";
import { Network, Bug, Workflow, Waypoints } from "lucide-react";
import { useConsole } from "@/lib/store";
import { fetchReasoningTrace } from "@/lib/data";
import { buildEngagementGraph, type EngagementGraphInput } from "@/lib/engagementGraph";
import type { ReasoningTrace } from "@/lib/types";
import { EngagementGraph } from "@/components/graph/EngagementGraph";
import { Panel, PanelHeader, PanelBody, Kpi, ViewHead } from "@/components/ui/primitives";
import { ErrorBoundary } from "@/components/ui/ErrorBoundary";

export default function GraphPage() {
  const {
    findings, chains, services, assets, content, hostRaw, history,
    activeEngagement, activeId, openFinding, openHost,
  } = useConsole();

  // The reasoning-provenance trace is component-local (served from runtime/reasoning_trace.json),
  // like diagnostics — the shared store doesn't carry it. Absent/failed fetch → undefined → the
  // overlay stays hidden and the existing view is unchanged.
  const [trace, setTrace] = useState<ReasoningTrace | undefined>(undefined);
  useEffect(() => {
    let live = true;
    setTrace(undefined);
    if (activeId) void fetchReasoningTrace(activeId).then((t) => { if (live) setTrace(t); });
    return () => { live = false; };
  }, [activeId]);

  // Key the graph input on the engagement's STABLE identity fields (target/name strings), not the
  // activeEngagement object ref. The store hands back a fresh engagement object on manifest polls even
  // when nothing changed; depending on the object would rebuild `input` — and both graph builds below —
  // every poll. With a stable `input`, the maximal KPI build and the view build recompute only when the
  // surface data (assets/services/findings/chains/…) actually changes.
  const engTarget = activeEngagement?.target;
  const engName = activeEngagement?.name;
  const input: EngagementGraphInput = useMemo(() => ({
    target: engTarget,
    engagementName: engName,
    assets, services, findings, chains, content, hostRaw, history, trace,
  }), [engTarget, engName, assets, services, findings, chains, content, hostRaw, history, trace]);

  // headline totals (full build — every surface + producer). One memoized maximal build; the view's
  // own (filtered) build lives in EngagementGraph. Both are keyed off the stable `input` above, so a
  // no-op poll re-renders neither.
  const totals = useMemo(
    () => buildEngagementGraph(input, { allRoutes: true, showServices: true, showAgents: true }).stats,
    [input],
  );

  const onOpenFinding = (id: string) => { const f = findings.find((x) => x.id === id); if (f) openFinding(f); };

  return (
    <>
      <ViewHead
        crumb="redstrike / exploration"
        title="Exploration graph"
        sub={activeEngagement?.target ? `${activeEngagement.target} · one connected view, recon → findings` : "one connected view of the engagement"}
      />

      <div className="mb-5 grid grid-cols-2 gap-3.5 lg:grid-cols-4">
        <Kpi label="Hosts" value={totals.host} icon={<Network size={16} />} note="in-scope surface" />
        <Kpi label="Endpoints" value={totals.route} icon={<Waypoints size={16} />} note="discovered routes" />
        <Kpi label="Findings" value={totals.finding} icon={<Bug size={16} />} note="on the graph" />
        <Kpi label="Attack chains" value={totals.chain} icon={<Workflow size={16} />} note="composed findings" />
      </div>

      <Panel>
        <PanelHeader
          title="Engagement graph"
          sub="scope → host → endpoint → finding → chain"
        />
        <PanelBody flush>
          <ErrorBoundary label="The engagement graph hit a malformed node field">
            <EngagementGraph input={input} onOpenFinding={onOpenFinding} onOpenHost={openHost} />
          </ErrorBoundary>
        </PanelBody>
      </Panel>
    </>
  );
}
