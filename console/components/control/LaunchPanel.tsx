"use client";

import { useState } from "react";
import { Rocket, Plus, FolderOpen, ShieldCheck, ShieldQuestion, Zap, Loader2, Square } from "lucide-react";
import { useControl } from "./ControlProvider";
import { Card, Pill, Select } from "@/components/ui/primitives";
import { cx } from "@/lib/format";

type Mode = "existing" | "new";

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-xs font-medium text-muted">{label}</span>
      {hint && <span className="ml-1.5 text-[11px] text-muted/70">{hint}</span>}
      <div className="mt-1">{children}</div>
    </label>
  );
}

const inputCls =
  "h-9 w-full rounded-lg border border-line bg-card2 px-2.5 text-sm outline-none placeholder:text-muted focus:border-brand/50";

export function LaunchPanel() {
  const { engagements, activeId, setActiveId, running, busy, doInit, doRun, doStop } = useControl();
  const [mode, setMode] = useState<Mode>(engagements.length ? "existing" : "new");

  // init fields
  const [client, setClient] = useState("");
  const [domains, setDomains] = useState("");
  const [authorizedBy, setAuthorizedBy] = useState("");
  const [cidrs, setCidrs] = useState("");
  const [windowDays, setWindowDays] = useState("");
  const [confirm, setConfirm] = useState(false);

  // run fields
  const [supervise, setSupervise] = useState(false); // default: autonomous — no per-command approvals
  const [allow, setAllow] = useState("");
  const [maxTurns, setMaxTurns] = useState("200");
  const [maxBudget, setMaxBudget] = useState("20");

  const toList = (s: string) => s.split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);

  const runConfig = () => ({
    // Autonomous (default): hand the gate `Bash`/`PowerShell`, which it reads as the `*`
    // pass-glob — every in-scope shell command runs WITHOUT deferring for approval. The scope
    // gate still DENIES out-of-scope targets and writes to governance files, so scope stays
    // enforced; only the per-command sign-off is waived. Supervised: only the operator's
    // explicit patterns pass; everything else defers to the Approvals panel.
    allow: supervise ? toList(allow) : ["Bash", "PowerShell"],
    max_turns: parseInt(maxTurns || "200", 10),
    max_budget: parseFloat(maxBudget || "20"),
  });

  const createEngagement = async () => {
    const r = await doInit({
      client: client.trim(),
      domains: toList(domains),
      authorized_by: authorizedBy.trim(),
      confirm_authorization: confirm,
      cidrs: toList(cidrs),
      ...(windowDays ? { window_days: parseInt(windowDays, 10) } : {}),
    });
    if (r?.ok) {
      // the new id is "<client-slug>-<date>"; the status refresh added it — pick the newest match
      const slug = client.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/(^-|-$)/g, "");
      setMode("existing");
      const match = engagements.find((e) => e.startsWith(slug));
      if (match) setActiveId(match);
    }
  };

  const canInit = client.trim() && toList(domains).length > 0 && authorizedBy.trim() && confirm;
  const canRun = !!activeId && !running;

  return (
    <Card className="p-5">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          <Rocket size={15} className="text-brand" /> Launch
        </h2>
        <div className="inline-flex rounded-lg border border-line bg-card2 p-0.5">
          {(["existing", "new"] as Mode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={cx(
                "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition",
                mode === m ? "bg-brand text-brand-fg" : "text-muted hover:text-fg",
              )}
            >
              {m === "existing" ? <FolderOpen size={13} /> : <Plus size={13} />}
              {m === "existing" ? "Run existing" : "New engagement"}
            </button>
          ))}
        </div>
      </div>

      {/* ---- new engagement (redstrike init) ---- */}
      {mode === "new" && (
        <div className="mb-4 space-y-3 border-b border-line pb-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Field label="Client">
              <input className={inputCls} value={client} onChange={(e) => setClient(e.target.value)} placeholder="Acme Corp" />
            </Field>
            <Field label="Authorized by">
              <input
                className={inputCls}
                value={authorizedBy}
                onChange={(e) => setAuthorizedBy(e.target.value)}
                placeholder="sec@acme / auth-ref"
              />
            </Field>
          </div>
          <Field label="Domains" hint="comma or newline separated">
            <input className={inputCls} value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="*.acme.com, api.acme.com" />
          </Field>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Field label="CIDRs" hint="optional">
              <input className={inputCls} value={cidrs} onChange={(e) => setCidrs(e.target.value)} placeholder="10.0.0.0/24" />
            </Field>
            <Field label="Window (days)" hint="optional">
              <input className={inputCls} type="number" min={1} value={windowDays} onChange={(e) => setWindowDays(e.target.value)} placeholder="14" />
            </Field>
          </div>
          <label className="flex items-start gap-2.5 rounded-lg border border-line bg-card2 p-3">
            <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} className="mt-0.5 h-4 w-4 accent-brand" />
            <span className="flex items-center gap-1.5 text-xs text-muted">
              <ShieldCheck size={14} className="shrink-0 text-emerald-400" />
              I confirm written authorization for this scope is on file (mirrors{" "}
              <code className="rounded bg-card px-1 py-0.5 text-[10px]">--i-confirm-authorization</code>).
            </span>
          </label>
          <button
            onClick={() => void createEngagement()}
            disabled={!canInit || busy}
            className={cx(
              "inline-flex h-9 items-center gap-1.5 rounded-lg bg-brand px-4 text-sm font-medium text-brand-fg transition hover:brightness-110",
              (!canInit || busy) && "cursor-not-allowed opacity-60",
            )}
          >
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />} Scaffold engagement
          </button>
        </div>
      )}

      {/* ---- run config (redstrike run --autonomous) ---- */}
      <div className="space-y-3">
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

        <Field label="Supervision" hint="how commands are cleared during the run">
          <div className="inline-flex w-full rounded-lg border border-line bg-card2 p-0.5">
            {([
              { v: false, label: "Autonomous", icon: Zap },
              { v: true, label: "Supervised", icon: ShieldQuestion },
            ] as const).map(({ v, label, icon: Icon }) => (
              <button
                key={label}
                type="button"
                onClick={() => setSupervise(v)}
                className={cx(
                  "inline-flex flex-1 items-center justify-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition",
                  supervise === v ? "bg-brand text-brand-fg" : "text-muted hover:text-fg",
                )}
              >
                <Icon size={13} /> {label}
              </button>
            ))}
          </div>
          <p className="mt-1.5 flex items-start gap-1.5 text-[11px] text-muted">
            <ShieldCheck size={13} className="mt-px shrink-0 text-emerald-400" />
            {supervise
              ? "Pauses for your approval on each shell command outside the allowlist below."
              : "Runs end to end within scope — no per-command approvals. The scope gate still blocks anything out of scope."}
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

        <div className="grid grid-cols-2 gap-3">
          <Field label="Max turns">
            <input className={inputCls} type="number" min={1} value={maxTurns} onChange={(e) => setMaxTurns(e.target.value)} />
          </Field>
          <Field label="Max budget (USD)">
            <input className={inputCls} type="number" min={0} step="0.5" value={maxBudget} onChange={(e) => setMaxBudget(e.target.value)} />
          </Field>
        </div>

        <div className="flex items-center gap-2 pt-1">
          {running ? (
            <>
              <Pill label="Run in progress" color="#22c55e" dot />
              <button
                onClick={() => void doStop()}
                disabled={busy}
                className="ml-auto inline-flex h-9 items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 text-sm font-medium text-rose-400 transition hover:bg-rose-500/20"
              >
                {busy ? <Loader2 size={14} className="animate-spin" /> : <Square size={13} />} Stop
              </button>
            </>
          ) : (
            <button
              onClick={() => void doRun(runConfig())}
              disabled={!canRun || busy}
              className={cx(
                "inline-flex h-9 items-center gap-1.5 rounded-lg bg-brand px-4 text-sm font-medium text-brand-fg transition hover:brightness-110",
                (!canRun || busy) && "cursor-not-allowed opacity-60",
              )}
            >
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Rocket size={14} />} Launch {supervise ? "supervised" : "autonomous"} run
            </button>
          )}
        </div>
      </div>
    </Card>
  );
}
