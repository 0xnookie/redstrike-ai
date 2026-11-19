"use client";

import { useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  Rocket, Plus, FolderOpen, ShieldCheck, ShieldQuestion, Zap, Loader2, Square,
  ChevronDown, Gauge, Bot, GitBranch,
} from "lucide-react";
import { useControl } from "./ControlProvider";
import { Panel, PanelHeader, PanelBody, Pill, Select } from "@/components/ui/primitives";
import { cx } from "@/lib/format";
import { useToast } from "@/components/ui/Toast";

type Mode = "existing" | "new" | "audit";
type Depth = "quick" | "standard" | "deep";

// Depth presets — pick an intent instead of hand-tuning the run ceilings.
// Agents stop at whichever ceiling (turns or budget) is reached first.
const DEPTH: Record<Depth, { label: string; turns: number; budget: number; note: string }> = {
  quick:    { label: "Quick",    turns: 60,  budget: 5,  note: "fast first-pass triage" },
  standard: { label: "Standard", turns: 200, budget: 20, note: "balanced coverage" },
  deep:     { label: "Deep",     turns: 500, budget: 60, note: "exhaustive hunt" },
};

const inputCls =
  "h-9 w-full rounded-lg border border-line bg-card2 px-2.5 text-sm outline-none placeholder:text-muted focus:border-fg/40";

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-muted">{label}</span>
      {hint && <span className="ml-1.5 text-[11px] text-muted/70">{hint}</span>}
      <div className="mt-1">{children}</div>
    </label>
  );
}

/* full-width segmented control */
function Seg<T extends string>({
  value, onChange, options,
}: { value: T; onChange: (v: T) => void; options: { v: T; label: string; icon?: LucideIcon }[] }) {
  return (
    <div className="inline-flex w-full rounded-lg border border-line bg-card2 p-0.5">
      {options.map(({ v, label, icon: Icon }) => (
        <button
          key={v}
          type="button"
          onClick={() => onChange(v)}
          className={cx(
            "inline-flex flex-1 items-center justify-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition",
            value === v ? "bg-brand text-brand-fg" : "text-muted hover:text-fg",
          )}
        >
          {Icon && <Icon size={13} />} {label}
        </button>
      ))}
    </div>
  );
}

export function LaunchPanel({ bare = false, onLaunched }: { bare?: boolean; onLaunched?: () => void } = {}) {
  const { engagements, activeId, setActiveId, running, busy, doInit, doAudit, doRun, doRunFor, doStop, auth, lastError } = useControl();
  const toast = useToast();
  const [mode, setMode] = useState<Mode>(engagements.length ? "existing" : "new");

  // scope / authorization (new engagement → redstrike init)
  const [client, setClient] = useState("");
  const [domains, setDomains] = useState("");
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [cidrs, setCidrs] = useState("");
  const [windowDays, setWindowDays] = useState("");
  const [confirm, setConfirm] = useState(false);

  // white-box source audit (→ redstrike audit <repo_url>)
  const [repoUrl, setRepoUrl] = useState("");
  const [branch, setBranch] = useState("");

  // run settings (shared by both modes → redstrike run)
  const [depth, setDepthState] = useState<Depth>("standard");
  const [supervise, setSupervise] = useState(false); // default: autonomous — runs unattended; dangerous steps still defer to Approvals
  const [allow, setAllow] = useState("");
  const [maxTurns, setMaxTurns] = useState(String(DEPTH.standard.turns));
  const [maxBudget, setMaxBudget] = useState(String(DEPTH.standard.budget));
  const [adv, setAdv] = useState(false);

  // picking a depth rewrites the ceilings; Advanced can still fine-tune them after.
  const setDepth = (d: Depth) => {
    setDepthState(d);
    setMaxTurns(String(DEPTH[d].turns));
    setMaxBudget(String(DEPTH[d].budget));
  };

  const toList = (s: string) => s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);

  // Autonomous (default): hand the gate `Bash`/`PowerShell` — the `*` pass-glob — so routine,
  // non-destructive shell commands run WITHOUT deferring. The scope gate still DENIES out-of-scope
  // targets. Even under this blanket allow, active-exploit / post-exploitation / destructive tools
  // still DEFER to the Approvals panel for operator sign-off, unless the operator pre-allows a
  // specific one with a narrow rule (e.g. `Bash(sqlmap *)`). Supervised: only the operator's patterns pass.
  const runConfig = () => ({
    allow: supervise ? toList(allow) : ["Bash", "PowerShell"],
    max_turns: parseInt(maxTurns || "200", 10),
    max_budget: parseFloat(maxBudget || "20"),
  });

  const initBody = () => ({
    client: client.trim(),
    domains: toList(domains),
    authorized_by: authorizedBy.trim(),
    confirm_authorization: confirm,
    ...(toList(cidrs).length ? { cidrs: toList(cidrs) } : {}),
    ...(windowDays ? { window_days: parseInt(windowDays, 10) } : {}),
  });

  // best-effort id resolution when an older backend doesn't echo `engagement`
  const slugMatch = () => {
    const slug = client.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
    return engagements.find((e) => e.startsWith(slug)) || "";
  };

  const createOnly = async () => {
    const r = await doInit(initBody());
    if (r?.ok) {
      const id = r.engagement || slugMatch();
      setMode("existing");
      if (id) setActiveId(id);
      toast(`Engagement ${id || "created"} scaffolded`);
      onLaunched?.();
    }
  };

  const createAndLaunch = async () => {
    const r = await doInit(initBody());
    if (!r?.ok) return;
    const id = r.engagement || slugMatch();
    if (!id) return;
    setMode("existing");
    setActiveId(id);
    const ok = await doRunFor(id, runConfig()); // explicit id — the new one isn't `activeId` yet this tick
    if (ok) { toast(`Run launched on ${id}`); onLaunched?.(); }
  };

  const launchExisting = async () => {
    const ok = await doRun(runConfig());
    if (ok) { toast(`Run launched on ${activeId}`); onLaunched?.(); }
  };

  // Audit a repository: the SAME authorization gate (confirm) applies; the plane clones + scaffolds
  // a source-granted engagement and launches it. We adopt the launched engagement id as active.
  const auditBody = () => ({
    repo_url: repoUrl.trim(),
    authorized_by: authorizedBy.trim(),
    confirm_authorization: confirm,
    ...(branch.trim() ? { branch: branch.trim() } : {}),
    ...(client.trim() ? { client: client.trim() } : {}),
    ...(windowDays ? { window_days: parseInt(windowDays, 10) } : {}),
    ...runConfig(),
  });

  const auditRepo = async () => {
    const r = await doAudit(auditBody());
    if (r?.ok) {
      const id = r.engagement || "";
      setMode("existing");
      if (id) setActiveId(id);
      toast(id ? `Source audit launched on ${id}` : "Source engagement scaffolded");
      onLaunched?.();
    }
  };

  const canInit = client.trim() && toList(domains).length > 0 && authorizedBy.trim() && confirm;
  const canAudit = repoUrl.trim() && authorizedBy.trim() && confirm;
  const canRun = !!activeId && !running;
  const modelReady = !auth || Object.values(auth.providers).some((p) => p.connected);

  /* ---- shared run settings (depth · supervision · allowlist · advanced) ---- */
  const runSettings = (withScope: boolean) => (
    <>
      <Field label="Depth" hint={`${maxTurns} turns · $${maxBudget} cap`}>
        <Seg
          value={depth}
          onChange={setDepth}
          options={[{ v: "quick", label: "Quick" }, { v: "standard", label: "Standard" }, { v: "deep", label: "Deep" }]}
        />
        <p className="mt-1.5 flex items-center gap-1.5 text-[11px] text-muted">
          <Gauge size={13} className="shrink-0 text-muted" />
          {DEPTH[depth].note} — agents resume until the engagement is complete or the turn/budget ceiling is reached, whichever comes first.
        </p>
      </Field>

      <Field label="Supervision">
        <Seg
          value={supervise ? "sup" : "auto"}
          onChange={(v) => setSupervise(v === "sup")}
          options={[{ v: "auto", label: "Autonomous", icon: Zap }, { v: "sup", label: "Supervised", icon: ShieldQuestion }]}
        />
        <p className="mt-1.5 flex items-start gap-1.5 text-[11px] text-muted">
          <ShieldCheck size={13} className="mt-px shrink-0 text-emerald-400" />
          {supervise
            ? "Pauses for your approval on each shell command outside the allowlist below."
            : "Runs the full engagement to completion unattended — recon through report, resuming as needed. The scope gate blocks out-of-scope targets, and exploitation, post-exploitation, and destructive steps still pause in the Approvals panel for your sign-off, just like an interactive run."}
        </p>
      </Field>

      {supervise && (
        <Field label="Allowlist" hint="one rule per line — everything else defers for approval">
          <textarea
            className={cx(inputCls, "h-20 resize-y py-2 font-mono text-xs")}
            value={allow}
            onChange={(e) => setAllow(e.target.value)}
            placeholder={"Bash(nmap *)\nBash(httpx *)"}
          />
        </Field>
      )}

      <div>
        <button
          type="button"
          onClick={() => setAdv((a) => !a)}
          className="inline-flex items-center gap-1 text-xs font-medium text-muted transition hover:text-fg"
        >
          <ChevronDown size={13} className={cx("transition", adv && "rotate-180")} /> Advanced
        </button>
        {adv && (
          <div className="mt-2 grid grid-cols-2 gap-3">
            {withScope && (
              <>
                <Field label="CIDRs" hint="optional">
                  <input className={inputCls} value={cidrs} onChange={(e) => setCidrs(e.target.value)} placeholder="10.0.0.0/24" />
                </Field>
                <Field label="Window (days)" hint="optional">
                  <input className={inputCls} type="number" min={1} value={windowDays} onChange={(e) => setWindowDays(e.target.value)} placeholder="14" />
                </Field>
              </>
            )}
            <Field label="Max turns">
              <input className={inputCls} type="number" min={1} value={maxTurns} onChange={(e) => setMaxTurns(e.target.value)} />
            </Field>
            <Field label="Max budget (USD)">
              <input className={inputCls} type="number" min={0} step="0.5" value={maxBudget} onChange={(e) => setMaxBudget(e.target.value)} />
            </Field>
          </div>
        )}
      </div>
    </>
  );

  const modelHint = !modelReady && (
    <p className="flex items-start gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/[0.06] p-2.5 text-[11px] text-amber-500/90">
      <Bot size={13} className="mt-px shrink-0" />
      No model provider connected — connect one in Settings → Agent runtimes so the launched agents have an engine.
    </p>
  );

  const primaryBtn =
    "inline-flex h-9 items-center gap-1.5 rounded-lg bg-brand px-4 text-sm font-medium text-brand-fg transition hover:brightness-110";
  const ghostBtn =
    "inline-flex h-9 items-center gap-1.5 rounded-lg border border-line px-3.5 text-sm font-medium text-fg transition hover:border-fg/30";

  const MODES: { m: Mode; label: string; icon: LucideIcon }[] = [
    { m: "existing", label: "Run existing", icon: FolderOpen },
    { m: "new", label: "New engagement", icon: Plus },
    { m: "audit", label: "Audit a repository", icon: GitBranch },
  ];
  const modeToggle = (
    <div className="inline-flex flex-wrap rounded-lg border border-line bg-card2 p-0.5">
      {MODES.map(({ m, label, icon: Icon }) => (
        <button
          key={m}
          onClick={() => setMode(m)}
          className={cx(
            "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition",
            mode === m ? "bg-brand text-brand-fg" : "text-muted hover:text-fg",
          )}
        >
          <Icon size={13} />
          {label}
        </button>
      ))}
    </div>
  );

  const content =
    mode === "new" ? (
      /* ---------- new engagement: scope → authorize → launch, one flow ---------- */
      <div className="space-y-3.5">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Client">
            <input className={inputCls} value={client} onChange={(e) => setClient(e.target.value)} placeholder="Acme Corp" />
          </Field>
          <Field label="Authorized by">
            <input className={inputCls} value={authorizedBy} onChange={(e) => setAuthorizedBy(e.target.value)} placeholder="sec@acme / auth-ref" />
          </Field>
        </div>
        <Field label="In-scope domains" hint="comma or newline separated">
          <input className={inputCls} value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="*.acme.com, api.acme.com" />
        </Field>

        {runSettings(true)}

        <label className="flex items-start gap-2.5 rounded-lg border border-line bg-card2 p-3">
          <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} className="mt-0.5 h-4 w-4 accent-brand" />
          <span className="flex items-center gap-1.5 text-xs text-muted">
            <ShieldCheck size={14} className="shrink-0 text-emerald-400" />
            I confirm written authorization for this scope is on file (mirrors{" "}
            <code className="rounded bg-card px-1 py-0.5 text-[10px]">--i-confirm-authorization</code>).
          </span>
        </label>

        {modelHint}

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button onClick={() => void createAndLaunch()} disabled={!canInit || busy} className={cx(primaryBtn, (!canInit || busy) && "cursor-not-allowed opacity-60")}>
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Rocket size={14} />} Create &amp; launch {supervise ? "supervised" : "autonomous"}
          </button>
          <button onClick={() => void createOnly()} disabled={!canInit || busy} className={cx(ghostBtn, (!canInit || busy) && "cursor-not-allowed opacity-60")}>
            <Plus size={14} /> Create only
          </button>
        </div>
        {lastError && <p className="text-xs text-rose-400">{lastError}</p>}
      </div>
    ) : mode === "audit" ? (
      /* ---------- audit a repository: paste a URL → white-box source audit ---------- */
      <div className="space-y-3.5">
        <Field label="Repository URL" hint="http(s):// or git:// — cloned read-only, no code is executed">
          <input className={inputCls} value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} placeholder="https://example.com/acme/payments.git" />
        </Field>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Branch" hint="optional">
            <input className={inputCls} value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="default branch" />
          </Field>
          <Field label="Authorized by">
            <input className={inputCls} value={authorizedBy} onChange={(e) => setAuthorizedBy(e.target.value)} placeholder="appsec@acme / auth-ref" />
          </Field>
        </div>

        {runSettings(false)}

        <label className="flex items-start gap-2.5 rounded-lg border border-line bg-card2 p-3">
          <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} className="mt-0.5 h-4 w-4 accent-brand" />
          <span className="flex items-center gap-1.5 text-xs text-muted">
            <ShieldCheck size={14} className="shrink-0 text-emerald-400" />
            I confirm written authorization to audit this source is on file (mirrors{" "}
            <code className="rounded bg-card px-1 py-0.5 text-[10px]">--i-confirm-authorization</code>).
          </span>
        </label>

        {modelHint}

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button onClick={() => void auditRepo()} disabled={!canAudit || busy} className={cx(primaryBtn, (!canAudit || busy) && "cursor-not-allowed opacity-60")}>
            {busy ? <Loader2 size={14} className="animate-spin" /> : <GitBranch size={14} />} Clone &amp; audit {supervise ? "supervised" : "autonomous"}
          </button>
        </div>
        {lastError && <p className="text-xs text-rose-400">{lastError}</p>}
      </div>
    ) : (
      /* ---------- run an existing engagement ---------- */
      <div className="space-y-3.5">
        <Field label="Engagement">
          {engagements.length ? (
            <Select wrapperClassName="w-full" value={activeId} onChange={(e) => setActiveId(e.target.value)}>
              <option value="" disabled>
                Select an engagement…
              </option>
              {engagements.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </Select>
          ) : (
            <p className="rounded-lg border border-dashed border-line bg-card2 px-3 py-2 text-xs text-muted">
              No engagements yet — scaffold one with “New engagement”.
            </p>
          )}
        </Field>

        {runSettings(false)}

        {modelHint}

        <div className="flex items-center gap-2 pt-1">
          {running ? (
            <>
              <Pill label="Run in progress" color="#22c55e" dot />
              <button onClick={() => void doStop()} disabled={busy} className="ml-auto inline-flex h-9 items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 text-sm font-medium text-rose-400 transition hover:bg-rose-500/20">
                {busy ? <Loader2 size={14} className="animate-spin" /> : <Square size={13} />} Stop
              </button>
            </>
          ) : (
            <button onClick={() => void launchExisting()} disabled={!canRun || busy} className={cx(primaryBtn, (!canRun || busy) && "cursor-not-allowed opacity-60")}>
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Rocket size={14} />} Launch {supervise ? "supervised" : "autonomous"} run
            </button>
          )}
        </div>
        {lastError && <p className="text-xs text-rose-400">{lastError}</p>}
      </div>
    );

  if (bare) {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between gap-2">
          <h2 className="flex items-center gap-2 text-sm font-semibold">
            <Rocket size={15} className="text-brand" /> Launch
          </h2>
          {modeToggle}
        </div>
        {content}
      </div>
    );
  }

  return (
    <Panel>
      <PanelHeader title="Launch" icon={<Rocket size={15} className="text-brand" />} actions={modeToggle} />
      <PanelBody>{content}</PanelBody>
    </Panel>
  );
}
