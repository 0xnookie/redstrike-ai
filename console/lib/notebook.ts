// Notebook builder — shapes the engagement's notebook.json ("what an engagement gathers that
// isn't a finding yet") into view-ready groups + KPIs. Pure + deterministic so the Notebook page
// stays a thin view over it (mirrors lib/siteMap.ts). Renders ONLY what the notebook actually holds;
// missing sections come back empty and the page shows honest empty states.

import type {
  Notebook, NotebookLead, NotebookSub, NotebookDns, NotebookNet, NotebookContentRow,
  NotebookDefense, NotebookOsint, NotebookEvidence, NotebookRoe, NotebookAccount,
} from "./types";

export type LeadTab = "active" | "promoted" | "dead";

export interface NotebookRecon {
  subdomains: NotebookSub[];
  dns: NotebookDns[];
  network: NotebookNet[];
  content: NotebookContentRow[];
  defenses: NotebookDefense[];
  osint: NotebookOsint[];
  sources: Record<string, string>;
}

export interface NotebookKpis {
  activeLeads: number; p1: number; testing: number; promoted: number; dead: number;
  hosts: number; hostsInScope: number; takeover: number;
  accountsActive: number; accountsTotal: number; tenants: number; roles: number;
  evidence: number; evidenceBytes: number;
}

export interface NotebookView {
  empty: boolean;
  target?: string;
  generatedAt?: string;
  leads: NotebookLead[];
  groups: Record<LeadTab, NotebookLead[]>;
  recon: NotebookRecon;
  reconCount: number;
  evidence: NotebookEvidence[];
  roe?: NotebookRoe;
  accounts: NotebookAccount[];
  kpis: NotebookKpis;
}

const arr = <T,>(v: T[] | undefined): T[] => (Array.isArray(v) ? v : []);
export const isActiveLead = (l: NotebookLead): boolean => l.status === "open" || l.status === "testing";

/** Active sort: priority asc (unset last), then testing before open; promoted/dead: priority then id. */
function sortActive(a: NotebookLead, b: NotebookLead): number {
  const pa = a.priority ?? 9, pb = b.priority ?? 9;
  if (pa !== pb) return pa - pb;
  const sa = a.status === "testing" ? 0 : 1, sb = b.status === "testing" ? 0 : 1;
  if (sa !== sb) return sa - sb;
  return (a.id || "").localeCompare(b.id || "");
}
function sortByPrio(a: NotebookLead, b: NotebookLead): number {
  const pa = a.priority ?? 9, pb = b.priority ?? 9;
  return pa - pb || (a.id || "").localeCompare(b.id || "");
}

export function buildNotebook(notebook: Notebook | undefined): NotebookView {
  const leads = arr(notebook?.leads).filter((l) => l && typeof l === "object" && l.id);
  const groups: Record<LeadTab, NotebookLead[]> = {
    active: leads.filter(isActiveLead).sort(sortActive),
    promoted: leads.filter((l) => l.status === "promoted").sort(sortByPrio),
    dead: leads.filter((l) => l.status === "dead").sort(sortByPrio),
  };

  const ri = notebook?.recon_intel ?? {};
  const recon: NotebookRecon = {
    subdomains: arr(ri.subdomains),
    dns: arr(ri.dns),
    network: arr(ri.network),
    content: arr(ri.content),
    defenses: arr(ri.defenses),
    osint: arr(ri.osint),
    sources: (ri.sources && typeof ri.sources === "object") ? ri.sources : {},
  };
  const reconCount = recon.subdomains.length + recon.dns.length + recon.network.length +
    recon.content.length + recon.defenses.length + recon.osint.length;

  const evidence = arr(notebook?.evidence).slice().sort(
    (a, b) => (b.captured_at ? +new Date(b.captured_at) : 0) - (a.captured_at ? +new Date(a.captured_at) : 0),
  );
  const accounts = arr(notebook?.test_accounts);
  const roe = notebook?.roe && typeof notebook.roe === "object" ? notebook.roe : undefined;

  const kpis: NotebookKpis = {
    activeLeads: groups.active.length,
    p1: groups.active.filter((l) => l.priority === 1).length,
    testing: leads.filter((l) => l.status === "testing").length,
    promoted: groups.promoted.length,
    dead: groups.dead.length,
    hosts: recon.subdomains.length,
    hostsInScope: recon.subdomains.filter((s) => s.scope === "in").length,
    takeover: recon.subdomains.filter((s) => s.scope === "takeover").length,
    accountsActive: accounts.filter((a) => a.status === "active").length,
    accountsTotal: accounts.length,
    tenants: new Set(accounts.map((a) => a.tenant).filter(Boolean)).size,
    roles: new Set(accounts.map((a) => a.role).filter(Boolean)).size,
    evidence: evidence.length,
    evidenceBytes: evidence.reduce((n, e) => n + (typeof e.size === "number" ? e.size : 0), 0),
  };

  const empty = leads.length === 0 && reconCount === 0 && evidence.length === 0 &&
    accounts.length === 0 && !roe;

  return {
    empty,
    target: notebook?.target,
    generatedAt: notebook?.generated_at,
    leads, groups, recon, reconCount, evidence, roe, accounts, kpis,
  };
}

/** Human bytes (shared with the Evidence panel + KPI). */
export function fmtBytes(n?: number): string {
  if (n == null || !isFinite(n)) return "—";
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB"]; let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}
