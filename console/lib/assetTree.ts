// Turn the flat asset list into a domain hierarchy for the asset mindmap.
//
// Hosts are inserted into a reverse-DNS trie (so a.b.example.com nests under b →
// example.com), single-child non-host chains are path-compressed (at→gv→wien.gv.at
// becomes one node), risk/findings/host counts are aggregated up every branch, and
// large flat groups of plain untested hosts are folded into alphabetical buckets so
// the tree stays navigable. Risky / has-findings hosts are kept OUT of buckets so
// they stay visible as named nodes. Pure structure — layout lives in the component.

import type { Asset, AssetKind } from "./types";

export type RiskLevel = "high" | "elevated" | "none";
export const RISK_RANK: Record<RiskLevel, number> = { none: 0, elevated: 1, high: 2 };

const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;
const HOST_KINDS = new Set<AssetKind>(["domain", "subdomain", "ip", "cidr"]);
const BUCKET_THRESHOLD = 14; // fold plain leaf hosts into letter buckets past this many siblings

export type NodeKind = "root" | "domain" | "host" | "bucket";

export interface TreeNode {
  id: string;
  label: string;          // display segment (or bucket letter, or root domain)
  full: string;           // full host/domain (for tooltip + host lookup)
  kind: NodeKind;
  asset?: Asset;          // set when kind === "host"
  scope: "in" | "out";
  coverage?: Asset["coverage"];
  findings: number;       // aggregate over subtree
  risk: RiskLevel;        // worst over subtree
  hostCount: number;      // hosts in subtree
  children: TreeNode[];
  // layout (filled per render by the component)
  x?: number; y?: number; depth?: number; angle?: number; r?: number;
}

export interface RiskInfo { level: RiskLevel; open: number }

interface Raw { label: string; full: string; children: Map<string, Raw>; asset?: Asset }

export function buildAssetTree(
  assets: Asset[],
  orgName: string,
  risk: Map<string, RiskInfo>,
): TreeNode {
  const hostAssets = assets.filter((a) => HOST_KINDS.has(a.kind));
  const domainHosts = hostAssets.filter((a) => !IP_RE.test(a.value));
  const ipHosts = hostAssets.filter((a) => IP_RE.test(a.value));

  let idc = 0;
  const nid = () => `t${idc++}`;
  const riskOf = (host: string): RiskLevel => risk.get(host)?.level ?? "none";

  // 1 — reverse-DNS trie of domain hosts
  const rawRoot: Raw = { label: "", full: "", children: new Map() };
  for (const a of domainHosts) {
    let node = rawRoot, path = "";
    for (const lab of a.value.split(".").reverse()) {
      path = path ? `${lab}.${path}` : lab;
      let child = node.children.get(lab);
      if (!child) { child = { label: lab, full: path, children: new Map() }; node.children.set(lab, child); }
      node = child;
    }
    node.asset = a;
  }

  const aggregate = (n: TreeNode) => {
    for (const k of n.children) {
      n.findings += k.findings;
      n.hostCount += k.hostCount;
      if (RISK_RANK[k.risk] > RISK_RANK[n.risk]) n.risk = k.risk;
    }
  };

  // 2 — Raw → TreeNode with path compression of single-child non-host chains
  const convert = (raw: Raw, isRoot: boolean): TreeNode => {
    let cur = raw;
    while (cur.children.size === 1 && !cur.asset) cur = [...cur.children.values()][0];
    const kids = [...cur.children.values()].map((c) => convert(c, false));
    const node: TreeNode = {
      id: nid(),
      label: isRoot ? (cur.full || orgName || "scope") : cur.label,
      full: cur.full,
      kind: cur.asset ? "host" : isRoot ? "root" : "domain",
      asset: cur.asset,
      scope: cur.asset?.scope ?? "in",
      coverage: cur.asset?.coverage,
      findings: cur.asset?.findings ?? 0,
      risk: cur.asset ? riskOf(cur.full) : "none",
      hostCount: cur.asset ? 1 : 0,
      children: kids,
    };
    aggregate(node);
    return node;
  };

  const root = convert(rawRoot, true);
  if (root.kind === "root" && !root.label) root.label = orgName || "scope";

  // 3 — IP hosts under their own branch
  if (ipHosts.length) {
    const ipNode: TreeNode = {
      id: nid(), label: "IP space", full: "", kind: "domain", scope: "in",
      findings: 0, risk: "none", hostCount: 0,
      children: ipHosts.map((a) => ({
        id: nid(), label: a.value, full: a.value, kind: "host" as const, asset: a,
        scope: a.scope, coverage: a.coverage, findings: a.findings,
        risk: riskOf(a.value), hostCount: 1, children: [] as TreeNode[],
      })),
    };
    aggregate(ipNode);
    root.children.push(ipNode);
  }
  // recompute root totals across all children (domains + ip branch)
  root.findings = root.children.reduce((s, c) => s + c.findings, 0);
  root.hostCount = root.children.reduce((s, c) => s + c.hostCount, 0);
  root.risk = root.children.reduce<RiskLevel>((r, c) => (RISK_RANK[c.risk] > RISK_RANK[r] ? c.risk : r), "none");

  // 4 — fold the long tail of plain untested hosts into letter buckets (depth-first)
  const bucketize = (n: TreeNode) => {
    n.children.forEach(bucketize);
    const plain: TreeNode[] = [], keep: TreeNode[] = [];
    for (const c of n.children) {
      (c.kind === "host" && c.children.length === 0 && c.risk === "none" && c.findings === 0 ? plain : keep).push(c);
    }
    if (plain.length > BUCKET_THRESHOLD) {
      const groups = new Map<string, TreeNode[]>();
      for (const c of plain) {
        const ch = (c.label[0] || "#").toLowerCase();
        const key = /[a-z]/.test(ch) ? ch : "#";
        (groups.get(key) ?? groups.set(key, []).get(key)!).push(c);
      }
      const buckets = [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([key, arr]) => {
        const b: TreeNode = {
          id: nid(), label: key === "#" ? "#" : key.toUpperCase(), full: "", kind: "bucket",
          scope: "in", findings: 0, risk: "none", hostCount: 0,
          children: arr.sort((x, y) => x.label.localeCompare(y.label)),
        };
        aggregate(b);
        return b;
      });
      n.children = [...keep, ...buckets];
    }
    // notable/branches first (risk then findings then name), buckets last
    n.children.sort((a, b) => {
      const ab = a.kind === "bucket" ? 1 : 0, bb = b.kind === "bucket" ? 1 : 0;
      return ab - bb || RISK_RANK[b.risk] - RISK_RANK[a.risk] || b.findings - a.findings || a.label.localeCompare(b.label);
    });
  };
  bucketize(root);

  return root;
}

/** Depth-first walk over every node in the tree. */
export function walkTree(root: TreeNode, fn: (n: TreeNode) => void): void {
  const stack = [root];
  while (stack.length) {
    const n = stack.pop()!;
    fn(n);
    for (const c of n.children) stack.push(c);
  }
}
