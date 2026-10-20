"use client";

import { useConsole } from "@/lib/store";
import { reportable, severityCounts } from "@/lib/stats";
import { ENGAGEMENT_STATUS, SEVERITY } from "@/lib/theme";
import { Dot } from "@/components/ui/primitives";

export function StatusBar() {
  const { activeEngagement: e, findings, chains, assets, mode } = useConsole();
  const st = ENGAGEMENT_STATUS[e.status];
  const inScope = assets.filter((a) => a.scope === "in").length;
  const rep = reportable(findings);
  const c = severityCounts(rep);

  return (
    <footer className="sticky bottom-0 z-20 flex h-7 items-center gap-3 overflow-x-auto whitespace-nowrap border-t border-line bg-sidebar px-3 font-mono text-[11px] text-muted scroll-thin sm:gap-4">
      <span className="flex items-center gap-1.5 text-fg">
        <Dot color={st.color} pulse={e.status === "running"} />
        {e.id}
      </span>
      <Sep />
      <span className="hidden sm:inline">scope:{inScope}</span>
      <span>rps:{e.rules.rate_limit_rps ?? "—"}</span>
      <Sep />
      <span>findings:{rep.length}</span>
      <span className="flex items-center gap-1.5">
        <b style={{ color: SEVERITY.critical.color }}>C{c.critical}</b>
        <b style={{ color: SEVERITY.high.color }}>H{c.high}</b>
        <b style={{ color: SEVERITY.medium.color }}>M{c.medium}</b>
        <b style={{ color: SEVERITY.low.color }}>L{c.low}</b>
      </span>
      <span>chains:{chains.length}</span>
      <span className="ml-auto flex items-center gap-1.5">
        <span className="h-1.5 w-1.5 rounded-full" style={{ background: mode === "empty" ? "#9ca3af" : "#22c55e" }} />
        {mode === "empty" ? "no data" : "live"}
      </span>
    </footer>
  );
}

function Sep() {
  return <span className="text-muted/40">·</span>;
}
