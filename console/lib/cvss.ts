// CVSS 3.1 base-score calculator — a faithful TS port of scripts/cvss.py so the
// console shows the same numbers as the engagement's authoritative scorer.
// Validated against the first.org reference vectors in that file.

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0.0 };
const PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

function roundup(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function cvssScore(vector?: string | null): number | null {
  if (!vector || typeof vector !== "string") return null;
  const m: Record<string, string> = {};
  for (const part of vector.trim().split("/")) {
    const [k, v] = part.split(":");
    if (k && k !== "CVSS") m[k] = v;
  }
  const need = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];
  if (need.some((k) => !(k in m))) return null;

  const scopeChanged = m.S === "C";
  const av = AV[m.AV], ac = AC[m.AC], ui = UI[m.UI];
  const pr = (scopeChanged ? PR_C : PR_U)[m.PR];
  const c = CIA[m.C], i = CIA[m.I], a = CIA[m.A];
  if ([av, ac, ui, pr, c, i, a].some((n) => n === undefined)) return null;

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  if (impact <= 0) return 0;
  const expl = 8.22 * av * ac * pr * ui;
  const raw = scopeChanged ? 1.08 * (impact + expl) : impact + expl;
  return roundup(Math.min(raw, 10));
}

export function cvssRating(score: number | null): string {
  if (score === null) return "—";
  if (score <= 0) return "None";
  if (score < 4.0) return "Low";
  if (score < 7.0) return "Medium";
  if (score < 9.0) return "High";
  return "Critical";
}
