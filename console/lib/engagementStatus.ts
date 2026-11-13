import type { Engagement, EngagementStatus } from "./types";

// A run log written this recently means a run is still going, even one this console didn't
// launch (a terminal run, or the control plane was restarted mid-run).
export const RUN_QUIET_MS = 5 * 60_000;

/** What the control plane says about runs; null = no plane connected (read-only viewer). */
export type ControlRuns = {
  live: string[];
  ended: Record<string, { how: "exited" | "stopped"; rc?: number | null }>;
};

/** The status shown everywhere. The data alone can't tell "running" from "finished without a
 *  report" (findings but no consolidated report read as running forever), so what actually
 *  happened to the run wins: a live run → running; ended this session → completed, or paused
 *  if the operator stopped it; a run log still being written → running; a run log gone quiet
 *  → completed. Only with no run log at all does the data-derived status stand. An explicit
 *  scope.yaml status is an operator override and always wins. */
export function resolveStatus(e: Engagement, ctl: ControlRuns | null, now: number): EngagementStatus {
  if (e.status_explicit) return e.status;
  if (ctl?.live.includes(e.id)) return "running";
  const ended = ctl?.ended[e.id];
  if (ended) return ended.how === "stopped" ? "paused" : "completed";
  if (e.run?.log) {
    const at = e.run.updated ? +new Date(e.run.updated) : 0;
    return at && now - at < RUN_QUIET_MS ? "running" : "completed";
  }
  return e.status;
}
