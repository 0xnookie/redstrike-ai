#!/usr/bin/env node
/*
 * Pure-builder unit test for the exploration graph's reasoning-provenance overlay.
 *
 * The console has no JS test runner, so this self-contained harness transpiles the pure TS builder
 * (console/lib/engagementGraph.ts + its relative deps) on the fly with the console's own TypeScript
 * compiler and exercises buildEngagementGraph() directly. It proves the CRITICAL contract: a trace's
 * fact node links to the EXISTING graph finding node (trace → finding), the full goal→intent→fact→
 * finding chain renders, a trace that references a non-existent finding adds no dangling node/edge,
 * and the "Why this finding" lineage slice never bleeds into a sibling finding under the same intent.
 *
 *   node scripts/test_reasoning_graph.cjs      # exit 0 = pass, 1 = fail
 */
"use strict";
const path = require("path");
const fs = require("fs");

const CONSOLE = path.resolve(__dirname, "..", "console");
const ts = require(path.join(CONSOLE, "node_modules", "typescript"));

// Resolve bare "./x" relative imports to "./x.ts" by registering the .ts extension, and transpile
// each .ts file to CommonJS as it's required (type-only imports are elided, so "./types" is never
// actually loaded). Pure modules only — these libs import no React/CSS.
require.extensions[".ts"] = function (module, filename) {
  const src = fs.readFileSync(filename, "utf8");
  const out = ts.transpileModule(src, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2019,
      esModuleInterop: true,
    },
    fileName: filename,
  });
  module._compile(out.outputText, filename);
};

const { buildEngagementGraph } = require(path.join(CONSOLE, "lib", "engagementGraph.ts"));

/* ---- tiny assert harness ---- */
let failed = 0;
function ok(cond, msg) {
  if (cond) { console.log("  ok   " + msg); }
  else { console.error("  FAIL " + msg); failed++; }
}

/* ---- fixture: two IDOR findings under one hypothesis, plus a GHOST trace finding ---- */
const F = (id) => ({
  id, composite: false, title: `IDOR ${id}`, asset: `https://acme.com/api/orders/${id}`,
  severity: "high", confidence: "confirmed", status: "verified",
  review: { verdict: "accepted", reviewer: "idor-verify" }, evidence: [], reproduction: [],
});

const input = {
  target: "acme.com",
  engagementName: "acme",
  assets: [{ id: "a1", value: "acme.com", kind: "domain", scope: "in", coverage: "tested", findings: 0 }],
  services: [],
  findings: [F("RS-2026-003"), F("RS-2026-004")],
  chains: [],
  trace: {
    version: 1,
    nodes: [
      { id: "goal:root", kind: "goal", label: "Assess acme.com", parent: null },
      { id: "intent:idor", kind: "intent", label: "Is IDOR present?", parent: "goal:root", category: "idor" },
      { id: "fact:RS-2026-003", kind: "fact", label: "GET /orders/3 → user B's order", parent: "intent:idor", finding_id: "RS-2026-003", evidence_ref: "idor/ev3.txt" },
      { id: "finding:RS-2026-003", kind: "finding", label: "IDOR 3", parent: "fact:RS-2026-003", finding_id: "RS-2026-003" },
      { id: "fact:RS-2026-004", kind: "fact", label: "GET /orders/4 → user C's order", parent: "intent:idor", finding_id: "RS-2026-004", evidence_ref: "idor/ev4.txt" },
      { id: "finding:RS-2026-004", kind: "finding", label: "IDOR 4", parent: "fact:RS-2026-004", finding_id: "RS-2026-004" },
      // GHOST: references a finding that is NOT in the engagement → must never reach the graph
      { id: "fact:RS-9999", kind: "fact", label: "phantom", parent: "intent:idor", finding_id: "RS-9999" },
      { id: "finding:RS-9999", kind: "finding", label: "phantom", parent: "fact:RS-9999", finding_id: "RS-9999" },
    ],
    edges: [
      { id: "e1", source: "goal:root", target: "intent:idor", rel: "spawns" },
      { id: "e2", source: "intent:idor", target: "fact:RS-2026-003", rel: "yields" },
      { id: "e3", source: "fact:RS-2026-003", target: "finding:RS-2026-003", rel: "proves" },
      { id: "e4", source: "intent:idor", target: "fact:RS-2026-004", rel: "yields" },
      { id: "e5", source: "fact:RS-2026-004", target: "finding:RS-2026-004", rel: "proves" },
      { id: "e6", source: "intent:idor", target: "fact:RS-9999", rel: "yields" },
      { id: "e7", source: "fact:RS-9999", target: "finding:RS-9999", rel: "proves" },
    ],
  },
};

const ids = (g) => new Set(g.nodes.map((n) => n.id));
const hasEdge = (g, a, b) => g.edges.some((e) => (e.source === a && e.target === b) || (e.source === b && e.target === a));

/* ---- 1. default: overlay OFF, existing view unchanged ---- */
const base = buildEngagementGraph(input, {});
ok(ids(base).has("find:RS-2026-003"), "[default] the finding node exists");
ok(!base.nodes.some((n) => n.kind === "fact" || n.kind === "intent" || n.kind === "goal"),
  "[default] NO provenance nodes when the overlay is off (existing view unchanged)");
ok(!base.edges.some((e) => e.rel === "provenance"), "[default] no provenance edges when off");

/* ---- 2. overlay ON: trace → finding link is correct ---- */
const prov = buildEngagementGraph(input, { showProvenance: true });
const pids = ids(prov);
ok(pids.has("prov:fact:RS-2026-003"), "[overlay] evidence node added for the finding");
ok(pids.has("prov:intent:idor"), "[overlay] hypothesis node added");
ok(pids.has("prov:goal:root"), "[overlay] goal node added");
ok(hasEdge(prov, "prov:fact:RS-2026-003", "find:RS-2026-003"),
  "[overlay] TRACE→FINDING: evidence node links to the EXISTING finding node");
ok(hasEdge(prov, "prov:intent:idor", "prov:fact:RS-2026-003"), "[overlay] hypothesis → evidence edge");
ok(hasEdge(prov, "prov:goal:root", "prov:intent:idor"), "[overlay] goal → hypothesis edge");
ok(prov.edges.filter((e) => e.rel === "provenance").every((e) => pids.has(e.source) && pids.has(e.target)),
  "[overlay] every provenance edge endpoint resolves to a real node (no dangling)");
ok(!pids.has("prov:fact:RS-9999") && !pids.has("find:RS-9999"),
  "[overlay] a trace node for a NON-EXISTENT finding is dropped (no orphan)");
ok(prov.stats.fact >= 2 && prov.stats.intent === 1 && prov.stats.goal === 1,
  "[overlay] stats count the provenance kinds");

/* ---- 3. "Why this finding": lineage slice never bleeds into a sibling finding ---- */
const slice = buildEngagementGraph(input, { lineageFinding: "RS-2026-003" });
const sids = ids(slice);
ok(sids.has("find:RS-2026-003"), "[lineage] keeps the target finding");
ok(sids.has("prov:fact:RS-2026-003") && sids.has("prov:intent:idor") && sids.has("prov:goal:root"),
  "[lineage] keeps the target's goal→intent→evidence ancestors");
ok(!sids.has("find:RS-2026-004"), "[lineage] EXCLUDES the sibling finding under the same hypothesis");
ok(!sids.has("prov:fact:RS-2026-004"), "[lineage] EXCLUDES the sibling's evidence");
ok(sids.has("scope"), "[lineage] keeps the scope root so the slice is anchored (root→finding)");

if (failed) { console.error(`\n${failed} assertion(s) FAILED`); process.exit(1); }
console.log("\nall reasoning-graph assertions passed");
