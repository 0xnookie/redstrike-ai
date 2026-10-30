"use client";

import { useEffect, useState } from "react";
import { X, Copy, Check, Globe } from "lucide-react";
import type { Finding } from "@/lib/types";
import { cvssScore } from "@/lib/cvss";
import { sevMeta, VERDICT } from "@/lib/theme";
import { fmtDate, verdictOf, assetHosts } from "@/lib/format";
import { useConsole } from "@/lib/store";
import { Pill, SeverityBadge, ConfidenceBadge } from "@/components/ui/primitives";
import { RichText } from "@/components/ui/RichText";

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  if (!children) return null;
  return (
    <div className="mb-4">
      <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted">{label}</div>
      <div className="text-sm leading-relaxed">{children}</div>
    </div>
  );
}

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1200); }}
      className="inline-flex items-center gap-1 rounded-md border border-line px-1.5 py-0.5 text-[10px] text-muted transition hover:text-fg"
      title={`Copy ${label ?? "to clipboard"}`}
    >
      {copied ? <Check size={11} /> : <Copy size={11} />}
      {copied ? "Copied" : label ?? "Copy"}
    </button>
  );
}

export function FindingDrawer({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const { openHost } = useConsole();
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  if (!finding) return null;
  const f = finding;
  // first real host named in the asset — opens that host's detail drawer (openHost
  // closes this finding drawer and opens the host one, so the two stay in sync)
  const host = assetHosts(f.asset)[0];
  const score = cvssScore(f.cvss_vector);
  const v = verdictOf(f);
  const cat = f.category || {};
  const maps = [
    cat.cwe && <Pill key="cwe" label={cat.cwe} color="#f472b6" />,
    cat.owasp && <Pill key="owasp" label={`OWASP ${cat.owasp}`} color="#60a5fa" />,
    cat.wstg && <Pill key="wstg" label={`WSTG ${cat.wstg}`} color="#818cf8" />,
    ...(f.attack_mapping || []).map((t) => <Pill key={t} label={`ATT&CK ${t}`} color="#f59e0b" />),
  ].filter(Boolean);

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm animate-fade-in" onClick={onClose} />
      <aside className="scroll-thin fixed inset-y-0 right-0 z-50 w-full max-w-xl animate-slide-in overflow-y-auto border-l border-line bg-card p-5">
        <div className="mb-4 flex items-start justify-between gap-4">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={f.severity} />
              {v && <Pill label={VERDICT[v].label} color={VERDICT[v].color} dot />}
              <ConfidenceBadge confidence={f.confidence} />
            </div>
            <h2 className="mt-2 text-lg font-semibold leading-tight">{f.title}</h2>
            <div className="mt-1 flex items-center gap-2 font-mono text-xs text-muted">{f.id}<CopyButton text={f.id} /></div>
            {f.potential_severity && f.potential_severity !== f.severity && (
              <div className="mt-2 flex items-center gap-2 text-xs">
                Demonstrated <SeverityBadge severity={f.severity} dot={false} /> · potential{" "}
                <SeverityBadge severity={f.potential_severity} dot={false} />
              </div>
            )}
          </div>
          <button onClick={onClose} aria-label="Close" className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line text-muted transition hover:text-fg">
            <X size={16} />
          </button>
        </div>

        {f.cvss_vector && (
          <Field label="CVSS 3.1">
            <span className="text-base font-semibold tabular-nums" style={{ color: sevMeta(f.severity).color }}>
              {score === null ? "?" : score.toFixed(1)}
            </span>
            <code className="ml-2 break-all text-xs text-muted">{f.cvss_vector}</code>
            <span className="ml-2 inline-block align-middle"><CopyButton text={f.cvss_vector} label="vector" /></span>
          </Field>
        )}
        <Field label="Affected asset">
          <code className="break-all rounded bg-card2 px-1.5 py-0.5 text-xs">{f.asset}</code>
          {host && (
            <div className="mt-1.5">
              <button
                onClick={() => openHost(host)}
                className="inline-flex items-center gap-1 text-xs text-sky-400 hover:underline"
                title={`Inspect ${host} in the asset map`}
              >
                <Globe size={12} /> Inspect {host}
              </button>
            </div>
          )}
        </Field>
        {maps.length > 0 && <Field label="Mappings"><div className="flex flex-wrap gap-1.5">{maps}</div></Field>}
        {f.impact && <Field label="Impact"><RichText text={f.impact} /></Field>}
        {f.reproduction?.length > 0 && (
          <Field label="Reproduction">
            <ol className="space-y-1.5">
              {f.reproduction.map((s, i) => (
                <li key={i} className="flex gap-2">
                  <span className="shrink-0 tabular-nums text-muted">{i + 1}.</span>
                  <RichText text={s} className="min-w-0 flex-1" />
                </li>
              ))}
            </ol>
          </Field>
        )}
        {f.evidence?.length > 0 && (
          <Field label="Evidence">
            <ul className="space-y-1.5">
              {f.evidence.map((e, i) => (
                <li key={i} className="rounded-md border border-line bg-card2 px-2.5 py-1.5">
                  <span className="font-mono text-xs text-brand">{e.type}</span>
                  <span className="text-xs text-muted"> · {e.ref}</span>
                  {e.sha256 && <div className="mt-0.5 break-all font-mono text-[10px] text-muted">{e.sha256}</div>}
                </li>
              ))}
            </ul>
          </Field>
        )}
        {f.remediation && <Field label="Remediation"><RichText text={f.remediation} /></Field>}
        {f.references && f.references.length > 0 && (
          <Field label="References">
            <ul className="space-y-1">
              {f.references.map((r) => (
                <li key={r}><a href={r} target="_blank" rel="noopener noreferrer" className="break-all text-sky-400 hover:underline">{r}</a></li>
              ))}
            </ul>
          </Field>
        )}
        {f.review?.verdict && (
          <Field label="Reviewer">
            <div className="flex flex-wrap items-center gap-2">
              <Pill label={VERDICT[f.review.verdict].label} color={VERDICT[f.review.verdict].color} dot />
              <span className="font-mono text-xs text-muted">{f.review.reviewer}</span>
              {f.review.reviewed_at && <span className="text-xs text-muted">· {fmtDate(f.review.reviewed_at)}</span>}
            </div>
            {f.review.notes && <p className="mt-1.5 text-xs text-muted"><RichText text={f.review.notes} /></p>}
          </Field>
        )}
      </aside>
    </>
  );
}
