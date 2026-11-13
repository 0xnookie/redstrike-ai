"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard, Target, Bug, Workflow, Network, Activity, Share2,
  Bot, FileText, Settings2, ListChecks, ShieldAlert, ListTree, NotebookPen, PlugZap, FileCode2, type LucideIcon,
} from "lucide-react";
import { cx } from "@/lib/format";
import { useConsole } from "@/lib/store";
import { useControl } from "@/components/control/ControlProvider";
import { reportable } from "@/lib/stats";
import { EngagementSwitcher } from "./EngagementSwitcher";

interface NavItem { href: string; label: string; icon: LucideIcon; }
const GROUPS: { title: string; items: NavItem[] }[] = [
  {
    title: "Operations",
    items: [
      { href: "/", label: "Dashboard", icon: LayoutDashboard },
      { href: "/engagements", label: "Engagements", icon: Target },
      { href: "/findings", label: "Findings", icon: Bug },
      { href: "/chains", label: "Attack chains", icon: Workflow },
      { href: "/assets", label: "Assets & scope", icon: Network },
      { href: "/sitemap", label: "Site map", icon: ListTree },
      { href: "/js-recon", label: "JS Recon", icon: FileCode2 },
      { href: "/notebook", label: "Notebook", icon: NotebookPen },
      { href: "/cve-intel", label: "CVE intel", icon: ShieldAlert },
      { href: "/orchestration", label: "Orchestration", icon: Share2 },
      { href: "/activity", label: "Activity", icon: Activity },
    ],
  },
  {
    title: "Framework",
    items: [
      { href: "/coverage", label: "Coverage", icon: ListChecks },
      { href: "/agents", label: "Agents", icon: Bot },
      { href: "/connections", label: "Connections", icon: PlugZap },
      { href: "/report", label: "Report", icon: FileText },
      { href: "/settings", label: "Settings", icon: Settings2 },
    ],
  },
];

export function Logo() {
  return (
    <div className="flex items-center gap-2.5" title="Redstrike">
      {/* the app mark — a black tile by design (the face's black is part of the art), so it
          reads as an app icon on the light sidebar and blends into the dark one */}
      <img
        src="/redstrike-logo.png"
        alt=""
        width={30}
        height={30}
        className="h-[30px] w-[30px] shrink-0 rounded-[9px] ring-1 ring-black/5 dark:ring-white/10"
      />
      <span className="font-sans text-[17px] font-bold leading-none tracking-tight text-fg">Redstrike</span>
    </div>
  );
}

// A nav badge: a count, and an optional tone — `hot` (red: open findings need attention) or
// `live` (green: something is running). A live badge with no count renders as a pulsing dot.
type BadgeTone = "hot" | "live";
interface NavBadge { n: number; tone?: BadgeTone }

// live nav counts derived from the loaded engagement data.
// Per-engagement counts reflect the ACTIVE engagement; engagements is the full list. 0 => no badge.
function useNavBadges(): Record<string, NavBadge> {
  const { engagements, findings, chains, assets, content, notebook, cveIntel, jsRecon } = useConsole();
  const { auth, conn, running } = useControl();
  const activeLeads = (notebook?.leads ?? []).filter((l) => l.status === "open" || l.status === "testing").length;
  const cves = (cveIntel?.cves ?? cveIntel?.entries ?? []).length;
  const connected = conn === "ready" ? Object.values(auth?.providers ?? {}).filter((p) => p.connected).length : 0;
  const anyRunning = engagements.some((e) => e.status === "running");
  return {
    "/engagements": { n: engagements.length, tone: anyRunning ? "live" : undefined },
    "/findings": { n: reportable(findings).length, tone: "hot" },
    "/chains": { n: chains.length },
    "/assets": { n: assets.length },
    "/sitemap": { n: content?.routes?.length ?? 0 },
    "/js-recon": { n: jsRecon?.totals?.endpoints ?? 0 },
    "/notebook": { n: activeLeads },
    "/cve-intel": { n: cves },
    "/orchestration": { n: 0, tone: running ? "live" : undefined }, // a run is streaming right now
    "/connections": { n: connected },
  };
}

const TONE_CLASS: Record<BadgeTone, string> = {
  hot: "bg-rose-500/[0.12] text-rose-500",
  live: "bg-emerald-500/[0.12] text-emerald-500",
};

export function Sidebar({ className, onNavigate }: { className?: string; onNavigate?: () => void }) {
  const pathname = usePathname();
  const badges = useNavBadges();

  const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));

  return (
    <aside className={cx("flex w-60 shrink-0 flex-col border-r border-line bg-sidebar", className)}>
      <div className="px-4 pb-4 pt-5">
        <Logo />
      </div>

      <nav className="scroll-thin flex-1 overflow-y-auto px-3 pb-4">
        {GROUPS.map((g) => (
          <div key={g.title} className="mb-5">
            <div className="px-2 pb-1.5 text-[11px] font-medium uppercase tracking-wider text-muted/80">{g.title}</div>
            <ul className="space-y-0.5">
              {g.items.map((it) => {
                const active = isActive(it.href);
                const Icon = it.icon;
                const badge = badges[it.href];
                const count = badge?.n ?? 0;
                const tone = badge?.tone;
                return (
                  <li key={it.href}>
                    <Link
                      href={it.href}
                      onClick={onNavigate}
                      className={cx(
                        "flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-sm transition",
                        active ? "bg-brand/10 font-medium text-brand" : "text-muted hover:bg-card2 hover:text-fg"
                      )}
                    >
                      <Icon size={17} className={active ? "text-brand" : ""} />
                      <span className="flex-1 truncate">{it.label}</span>
                      {count > 0 ? (
                        <span
                          className={cx(
                            "shrink-0 rounded-full px-1.5 py-0.5 text-[10px] font-mono leading-none tabular-nums",
                            tone ? TONE_CLASS[tone] : active ? "bg-brand/15 text-brand" : "bg-card2 text-faint"
                          )}
                        >
                          {count}
                        </span>
                      ) : tone === "live" ? (
                        <span className="live-dot mr-1" aria-label="live" />
                      ) : null}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      <EngagementSwitcher onNavigate={onNavigate} />
    </aside>
  );
}
