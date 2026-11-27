"use client";

import { useState } from "react";
import type { LucideIcon } from "lucide-react";
import {
  Rocket, Plus, FolderOpen, ShieldCheck, ShieldQuestion, Zap, Loader2, Square,
  ChevronDown, Gauge, Bot, GitBranch, AlertTriangle,
} from "lucide-react";
import { useControl } from "./ControlProvider";
import { Panel, PanelHeader, PanelBody, Pill, Select } from "@/components/ui/primitives";
import { cx } from "@/lib/format";
import { useToast } from "@/components/ui/Toast";

type Mode = "existing" | "new" | "audit";
type Depth = "quick" | "standard" | "deep";
// which action is currently awaiting the plane — drives the precise in-flight button label
type Pending = "" | "create" | "createonly" | "launch" | "audit";

// Depth presets — pick an intent instead of hand-tuning the run ceilings.
// Agents stop at whichever ceiling (turns or budget) is reached first.
const DEPTH: Record<Depth, { label: string; turns: number; budget: number; note: string }> = {
  quick:    { label: "Quick",    turns: 60,  budget: 5,  note: "fast first-pass triage" },
  standard: { label: "Standard", turns: 200, budget: 20, note: "balanced coverage" },
  deep:     { label: "Deep",     turns: 500, budget: 60, note: "exhaustive hunt" },
};

const inputCls =
  "h-9 w-full rounded-lg border border-line bg-card2 px-2.5 text-sm outline-none placeholder:text-muted focus:border-fg/40";

function Field({
  label, hint, required, error, children,
}: { label: string; hint?: string; required?: boolean; error?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-muted">
        {label}
        {required && <span className="ml-0.5 text-rose-400" aria-hidden>*</span>}
      </span>
      {hint && <span className="ml-1.5 text-[11px] text-muted/70">{hint}</span>}
      <div className="mt-1">{children}</div>
      {error && <span className="mt-1 block text-[11px] text-rose-400">{error}</span>}
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
          aria-pressed={value === v}
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

// "a", "a and b", "a, b and c" — for the "still needed" launch-readiness hint
const needList = (items: string[]) =>
  items.length <= 1 ? (items[0] ?? "") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;

// lenient repo-URL shape: an http(s)/git/ssh scheme URL, or an scp-style git remote (git@host:path)
const repoUrlOk = (u: string) =>
  /^(https?|git|ssh):\/\/\S+$/i.test(u) || /^[\w.-]+@[\w.-]+:\S+$/i.test(u);

export function LaunchPanel({ bare = false, onLaunched }: { bare?: boolean; onLaunched?: () => void } = {}) {
  const { engagements, activeId, setActiveId, running, busy, doInit, doAudit, doRun, doRunFor, doStop, auth, lastError } = useControl();
  const toast = useToast();
  const [mode, setModeState] = useState<Mode>(engagements.length ? "existing" : "new");
  const [pending, setPending] = useState<Pending>("");

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

  // Switching mode re-arms the authorization gate: the confirmation is asserted against a
  // specific target/scope, so it must be re-affirmed when the target changes — never carried
  // silently from one mode into another.
  const setMode = (m: Mode) => {
    setModeState(m);
    setConfirm(false);
  };

  // picking a depth rewrites the ceilings; Advanced can still fine-tune them after.
  const setDepth = (d: Depth) => {
    setDepthState(d);
    setMaxTurns(String(DEPTH[d].turns));
    setMaxBudget(String(DEPTH[d].budget));
  };

  const toList = (s: string) => s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);
  const parsedDomains = toList(domains);

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
    domains: parsedDomains,
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
    setPending("createonly");
    try {
      const r = await doInit(initBody());
      if (r?.ok) {
        const id = r.engagement || slugMatch();
        setModeState("existing");
        if (id) setActiveId(id);
        toast(`Engagement ${id || "created"} scaffolded`);
        onLaunched?.();
      }
    } finally {
      setPending("");
    }
  };

  const createAndLaunch = async () => {
    setPending("create");
    try {
      const r = await doInit(initBody());
      if (!r?.ok) return;
      const id = r.engagement || slugMatch();
      if (!id) return;
      setModeState("existing");
      setActiveId(id);
      setPending("launch");
      const ok = await doRunFor(id, runConfig()); // explicit id — the new one isn't `activeId` yet this tick
      if (ok) { toast(`Run launched on ${id}`); onLaunched?.(); }
    } finally {
      setPending("");
    }
  };

  const launchExisting = async () => {
    setPending("launch");
    try {
      const ok = await doRun(runConfig());
      if (ok) { toast(`Run launched on ${activeId}`); onLaunched?.(); }
    } finally {
      setPending("");
    }
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
    setPending("audit");
    try {
      const r = await doAudit(auditBody());
      if (r?.ok) {
        const id = r.engagement || "";
        setModeState("existing");
        if (id) setActiveId(id);
        toast(id ? `Source audit launched on ${id}` : "Source engagement scaffolded");
        onLaunched?.();
      }
    } finally {
      setPending("");
    }
  };

  const repoValid = repoUrlOk(repoUrl.trim());
  const canInit = Boolean(client.trim() && parsedDomains.length > 0 && authorizedBy.trim() && confirm);
  const canAudit = Boolean(repoUrl.trim() && repoValid && authorizedBy.trim() && confirm);
  const canRun = !!activeId && !running;
  const modelReady = !auth || Object.values(auth.providers).some((p) => p.connected);

  // launch-readiness, split so the authorization gate owns the confirm step (it emphasizes
  // itself) while this lists only the still-empty scope fields
  const missingNewFields = [
    !client.trim() && "a client name",
    parsedDomains.length === 0 && "an in-scope domain",
    !authorizedBy.trim() && "who authorized it",
  ].filter(Boolean) as string[];
  const missingAuditFields = [
    !repoUrl.trim() && "a repository URL",
    repoUrl.trim() && !repoValid && "a valid repository URL",
    !authorizedBy.trim() && "who authorized it",
  ].filter(Boolean) as string[];
  const newFieldsReady = missingNewFields.length === 0;
  const auditFieldsReady = missingAuditFields.length === 0 && Boolean(repoUrl.trim()) && repoValid;

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
          aria-expanded={adv}
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

  // The authorization gate — a clearly delineated, labelled step. It turns green once confirmed,
  // and amber-highlights when it's the ONLY thing left before launch so the operator can't miss it.
  const authGate = (forSource: boolean, emphasize: boolean) => (
    <div
      className={cx(
        "rounded-xl border p-3.5 transition",
        confirm
          ? "border-emerald-500/50 bg-emerald-500/[0.06]"
          : emphasize
            ? "border-amber-500/45 bg-amber-500/[0.05] ring-1 ring-amber-500/20"
            : "border-line bg-card2",
      )}
    >
      <div className="flex items-center gap-2">
        <ShieldCheck size={15} className={cx("shrink-0", confirm ? "text-emerald-400" : "text-muted")} />
        <span className="text-xs font-semibold text-fg-strong">Authorization required</span>
      </div>
      <label className="mt-2.5 flex cursor-pointer items-start gap-2.5">
        <input
          type="checkbox"
          checked={confirm}
          onChange={(e) => setConfirm(e.target.checked)}
          className="mt-0.5 h-4 w-4 accent-brand"
        />
        <span className="text-xs leading-relaxed text-muted">
          I confirm written authorization {forSource ? "to audit this source" : "for this scope"} is on file (mirrors{" "}
          <code className="rounded bg-card px-1 py-0.5 text-[10px]">--i-confirm-authorization</code>).
        </span>
      </label>
      {emphasize && !confirm && (
        <p className="mt-2 pl-[26px] text-[11px] text-amber-500/90">Confirm authorization to enable launch.</p>
      )}
    </div>
  );

  const modelHint = !modelReady && (
    <p className="flex items-start gap-1.5 rounded-lg border border-amber-500/30 bg-amber-500/[0.06] p-2.5 text-[11px] text-amber-500/90" role="status">
      <Bot size={13} className="mt-px shrink-0" />
      No model provider connected — connect one in Settings → Agent runtimes so the launched agents have an engine.
    </p>
  );

  const errorBanner = lastError && (
    <p className="flex items-start gap-1.5 rounded-lg border border-rose-500/30 bg-rose-500/[0.06] p-2.5 text-[11px] text-rose-400" role="alert">
      <AlertTriangle size={13} className="mt-px shrink-0" />
      {lastError}
    </p>
  );

  const readyHint = (items: string[]) =>
    !busy && items.length > 0 ? (
      <p className="text-[11px] text-faint" aria-live="polite">Still needed: {needList(items)}.</p>
    ) : null;

  const primaryBtn =
    "inline-flex h-9 items-center gap-1.5 rounded-lg bg-brand px-4 text-sm font-medium text-brand-fg transition hover:brightness-110";
  const ghostBtn =
    "inline-flex h-9 items-center gap-1.5 rounded-lg border border-line px-3.5 text-sm font-medium text-fg transition hover:border-fg/30";
  const verb = supervise ? "supervised" : "autonomous";

  const MODES: { m: Mode; label: string; icon: LucideIcon }[] = [
    { m: "existing", label: "Run existing", icon: FolderOpen },
    { m: "new", label: "New engagement", icon: Plus },
    { m: "audit", label: "Audit a repository", icon: GitBranch },
  ];
  const modeToggle = (
    <div className="inline-flex flex-wrap rounded-lg border border-line bg-card2 p-0.5" role="tablist" aria-label="Engagement source">
      {MODES.map(({ m, label, icon: Icon }) => (
        <button
          key={m}
          role="tab"
          aria-selected={mode === m}
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
          <Field label="Client" required hint="names the engagement">
            <input className={inputCls} value={client} onChange={(e) => setClient(e.target.value)} placeholder="Acme Corp" autoFocus />
          </Field>
          <Field label="Authorized by" required hint="person or auth reference">
            <input className={inputCls} value={authorizedBy} onChange={(e) => setAuthorizedBy(e.target.value)} placeholder="sec@acme / auth-ref" />
          </Field>
        </div>
        <Field label="In-scope domains" required hint="comma or newline separated">
          <input className={inputCls} value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="*.acme.com, api.acme.com" />
        </Field>
        {parsedDomains.length > 0 && (
          <div className="flex flex-wrap gap-1.5" aria-label="Parsed scope">
            {parsedDomains.map((d) => (
              <span
                key={d}
                className="inline-flex items-center gap-1.5 rounded-full border border-line bg-card2 px-2.5 py-1 font-mono text-[11px] text-muted"
              >
                <span className="h-1.5 w-1.5 rounded-full bg-fg/40" />
                {d}
              </span>
            ))}
          </div>
        )}

        {runSettings(true)}

        {authGate(false, newFieldsReady)}

        {modelHint}

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button onClick={() => void createAndLaunch()} disabled={!canInit || busy} className={cx(primaryBtn, (!canInit || busy) && "cursor-not-allowed opacity-60")}>
            {pending === "create" ? (
              <><Loader2 size={14} className="animate-spin" /> Scaffolding…</>
            ) : pending === "launch" ? (
              <><Loader2 size={14} className="animate-spin" /> Launching…</>
            ) : (
              <><Rocket size={14} /> Create &amp; launch {verb}</>
            )}
          </button>
          <button onClick={() => void createOnly()} disabled={!canInit || busy} className={cx(ghostBtn, (!canInit || busy) && "cursor-not-allowed opacity-60")}>
            {pending === "createonly" ? (
              <><Loader2 size={14} className="animate-spin" /> Scaffolding…</>
            ) : (
              <><Plus size={14} /> Create only</>
            )}
          </button>
        </div>
        {readyHint(missingNewFields)}
        {errorBanner}
      </div>
    ) : mode === "audit" ? (
      /* ---------- audit a repository: paste a URL → white-box source audit ---------- */
      <div className="space-y-3.5">
        <Field
          label="Repository URL"
          required
          hint="http(s):// or git:// — cloned read-only, no code is executed"
          error={repoUrl.trim() && !repoValid ? "Enter an http(s)://, git://, or git@host:path URL." : undefined}
        >
          <input className={inputCls} value={repoUrl} onChange={(e) => setRepoUrl(e.target.value)} placeholder="https://example.com/acme/payments.git" autoFocus />
        </Field>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <Field label="Branch" hint="optional — default branch">
            <input className={inputCls} value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="default branch" />
          </Field>
          <Field label="Authorized by" required hint="person or auth reference">
            <input className={inputCls} value={authorizedBy} onChange={(e) => setAuthorizedBy(e.target.value)} placeholder="appsec@acme / auth-ref" />
          </Field>
        </div>

        {runSettings(false)}

        {authGate(true, auditFieldsReady)}

        {modelHint}

        <div className="flex flex-wrap items-center gap-2 pt-1">
          <button onClick={() => void auditRepo()} disabled={!canAudit || busy} className={cx(primaryBtn, (!canAudit || busy) && "cursor-not-allowed opacity-60")}>
            {pending === "audit" ? (
              <><Loader2 size={14} className="animate-spin" /> Cloning &amp; scaffolding…</>
            ) : (
              <><GitBranch size={14} /> Clone &amp; audit {verb}</>
            )}
          </button>
        </div>
        {pending === "audit" && (
          <p className="text-[11px] text-faint">Cloning read-only can take a moment for a large repository — the run stream opens once it starts.</p>
        )}
        {readyHint(missingAuditFields)}
        {errorBanner}
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
            <button
              type="button"
              onClick={() => setMode("new")}
              className="flex w-full items-center gap-2 rounded-lg border border-dashed border-line bg-card2 px-3 py-2.5 text-left text-xs text-muted transition hover:border-fg/30 hover:text-fg"
            >
              <Plus size={14} className="shrink-0" />
              No engagements yet — scaffold one with “New engagement”.
            </button>
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
              {pending === "launch" ? (
                <><Loader2 size={14} className="animate-spin" /> Launching…</>
              ) : (
                <><Rocket size={14} /> Launch {verb} run</>
              )}
            </button>
          )}
        </div>
        {!busy && !activeId && engagements.length > 0 && (
          <p className="text-[11px] text-faint">Select an engagement above to launch.</p>
        )}
        {errorBanner}
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
