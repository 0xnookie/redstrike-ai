import { Radar, Wrench, Bug, ShieldCheck, ShieldAlert, Workflow, FileText, StickyNote, type LucideIcon } from "lucide-react";
import type { ActivityKind } from "@/lib/types";

export const ACTIVITY_ICON: Record<ActivityKind, LucideIcon> = {
  recon: Radar,
  tool_use: Wrench,
  finding: Bug,
  review: ShieldCheck,
  approval: ShieldAlert,
  chain: Workflow,
  report: FileText,
  note: StickyNote,
};
