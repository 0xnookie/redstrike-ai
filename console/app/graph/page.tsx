"use client";

import { useMemo } from "react";
import { Network, Bug, Workflow, Waypoints } from "lucide-react";
import { useConsole } from "@/lib/store";
import { buildEngagementGraph, type EngagementGraphInput } from "@/lib/engagementGraph";
import { EngagementGraph } from "@/components/graph/EngagementGraph";
import { Panel, PanelHeader, PanelBody, Kpi, ViewHead } from "@/components/ui/primitives";

export default function GraphPage() {
  const {
    findings, chains, services, assets, content, hostRaw, history,
    activeEngagement, openFinding, openHost,
  } = useConsole();

  const input: EngagementGraphInput = useMemo(() => ({
    target: activeEngagement?.target,
    engagementName: activeEngagement?.name,
    assets, services, findings, chains, content, hostRaw, history,
  }), [activeEngagement, assets, services, findings, chains, content, hostRaw, history]);

  // headline totals (full build — every surface + producer)
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
          <EngagementGraph input={input} onOpenFinding={onOpenFinding} onOpenHost={openHost} />
        </PanelBody>
      </Panel>
    </>
  );
}
