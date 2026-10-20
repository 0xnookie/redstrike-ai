import { Fragment } from "react";

/**
 * Render a finding's prose field (impact / reproduction step / remediation /
 * reviewer note) with embedded payloads shown as code.
 *
 * Two mechanisms, in priority order:
 *   1. Markdown-style inline code spans — `like this` — the authored convention
 *      (see skills/_contract/finding.schema.json). Rendered verbatim.
 *   2. A conservative auto-detector for payloads that older findings left un-
 *      backticked: HTTP request lines (optionally with a JSON body), standalone
 *      JSON objects, and `curl …` commands.
 *
 * Everything is plain React text, so quotes, `--`, `<`, `>` and the like render
 * exactly as written (escaped) — nothing is re-interpreted or corrupted.
 */

// HTTP request line (+ optional JSON body) | standalone JSON object | curl command
const AUTO =
  /(\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\/\S*(?:\s+\{[^{}]*\})?)|(\{\s*"[^{}]*\})|(\bcurl\b[^\n]*?(?=\s+->|\s{2,}\(|$))/g;

interface Tok { code: boolean; text: string }

function splitBackticks(text: string): Tok[] {
  const out: Tok[] = [];
  const re = /`([^`]+)`/g;
  let last = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push({ code: false, text: text.slice(last, m.index) });
    out.push({ code: true, text: m[1] });
    last = re.lastIndex;
  }
  if (last < text.length) out.push({ code: false, text: text.slice(last) });
  return out;
}

function splitAuto(text: string): Tok[] {
  const out: Tok[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  AUTO.lastIndex = 0;
  while ((m = AUTO.exec(text))) {
    if (m.index > last) out.push({ code: false, text: text.slice(last, m.index) });
    let code = m[0];
    // give back trailing prose punctuation unless the span ends in a payload char
    // (a JSON `}`, a quote) — so `POST /tokens,` → `POST /tokens` + ", ".
    let trail = "";
    if (!/[}"'`]$/.test(code)) {
      const p = code.match(/[.,;:]+$/);
      if (p) { trail = p[0]; code = code.slice(0, code.length - trail.length); }
    }
    out.push({ code: true, text: code });
    last = m.index + m[0].length - trail.length;
  }
  if (last < text.length) out.push({ code: false, text: text.slice(last) });
  return out;
}

function tokenize(text: string): Tok[] {
  // backticks first (authored, authoritative); only auto-scan the plain gaps
  return splitBackticks(text).flatMap((t) => (t.code ? [t] : splitAuto(t.text)));
}

function Code({ children }: { children: string }) {
  return (
    <code className="whitespace-pre-wrap break-words rounded bg-card2 px-1.5 py-0.5 font-mono text-[0.85em] text-fg [overflow-wrap:anywhere]">
      {children}
    </code>
  );
}

/** Inline rich text — payloads become <code>, prose stays prose. */
export function RichText({ text, className }: { text?: string; className?: string }) {
  if (!text) return null;
  const toks = tokenize(text);
  return (
    <span className={className}>
      {toks.map((t, i) => (t.code ? <Code key={i}>{t.text}</Code> : <Fragment key={i}>{t.text}</Fragment>))}
    </span>
  );
}
