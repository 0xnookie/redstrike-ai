// Live CVE feed for the "What's New in Cyber" dashboard section.
//
// The console is a static export with no backend, so the feed is fetched
// CLIENT-SIDE from a public, CORS-enabled, no-auth CVE DATA service (public
// vulnerability-data infrastructure — not a methodology source). It yields the
// real 7-/30-day detection counts (via totalResults) and the newest records.
//
// Swap `CVE_FEED.base` to self-host or mirror. For an air-gapped engagement,
// serve a `cve_feed.json` next to the console: that pins the feed and disables
// live fetching. If the live fetch fails (offline / rate-limited), the console
// keeps whatever feed it already has (the bundled snapshot), so it never breaks.

import type { CveFeed, CveItem, Severity } from "./types";

export const CVE_FEED = {
  /** Public CVE data service, CORS-enabled, no auth. One constant → easy to swap. */
  base: "https://services.nvd.nist.gov/rest/json/cves/2.0",
  listWindowHours: 24, // pull the trailing day, then sort newest-first client-side
  listSize: 12,
  refreshMs: 15 * 60 * 1000, // re-poll every 15 min
};

/** Authoritative record page for a CVE id (full CVSS vector, references, CPEs). */
export function cveRecordUrl(id: string): string {
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`;
}

const SEV_MAP: Record<string, Severity> = {
  CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", NONE: "info",
};

// NVD wants yyyy-MM-ddTHH:mm:ss.SSS (UTC); url-encode the colons.
function nvdDate(d: Date): string {
  return encodeURIComponent(d.toISOString().slice(0, 23));
}

function cvssOf(cve: any): { score?: number; sev?: Severity } {
  const m = cve?.metrics ?? {};
  for (const k of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const arr = m[k];
    if (Array.isArray(arr) && arr.length) {
      const d = arr[0].cvssData ?? {};
      const sevRaw = String(d.baseSeverity ?? arr[0].baseSeverity ?? "").toUpperCase();
      return {
        score: typeof d.baseScore === "number" ? d.baseScore : undefined,
        sev: SEV_MAP[sevRaw],
      };
    }
  }
  return {};
}

function toItem(v: any): CveItem {
  const cve = v?.cve ?? v ?? {};
  const descs: any[] = Array.isArray(cve.descriptions) ? cve.descriptions : [];
  const summary = descs.find((x) => x?.lang === "en")?.value ?? descs[0]?.value ?? "";
  const { score, sev } = cvssOf(cve);
  let published: string = cve.published ?? cve.lastModified ?? "";
  if (published && !/(Z|[+-]\d\d:?\d\d)$/.test(published)) published += "Z"; // NVD omits the tz → it's UTC
  return { id: cve.id, summary, severity: sev, cvss: score, published };
}

async function getJson(url: string, signal?: AbortSignal): Promise<any> {
  const res = await fetch(url, { signal, headers: { Accept: "application/json" }, cache: "no-store" });
  if (!res.ok) throw new Error(`CVE feed HTTP ${res.status}`);
  return res.json();
}

async function totalSince(hoursAgo: number, now: Date, signal?: AbortSignal): Promise<number> {
  const start = new Date(now.getTime() - hoursAgo * 3_600_000);
  const url = `${CVE_FEED.base}?pubStartDate=${nvdDate(start)}&pubEndDate=${nvdDate(now)}&resultsPerPage=1&noRejected`;
  const j = await getJson(url, signal);
  return Number(j?.totalResults) || 0;
}

/** Fetch + normalize a live feed. Throws on network / CORS / empty — caller keeps the fallback. */
export async function fetchLiveCveFeed(signal?: AbortSignal): Promise<CveFeed> {
  const now = new Date();
  const listStart = new Date(now.getTime() - CVE_FEED.listWindowHours * 3_600_000);
  const listUrl = `${CVE_FEED.base}?pubStartDate=${nvdDate(listStart)}&pubEndDate=${nvdDate(now)}&resultsPerPage=2000&noRejected`;

  const [listJson, count7d, count30d] = await Promise.all([
    getJson(listUrl, signal),
    totalSince(7 * 24, now, signal),
    totalSince(30 * 24, now, signal),
  ]);

  const vulns: any[] = Array.isArray(listJson?.vulnerabilities) ? listJson.vulnerabilities : [];
  const items = vulns
    .map(toItem)
    .filter((it) => it.id && it.published)
    .sort((a, b) => +new Date(b.published) - +new Date(a.published))
    .slice(0, CVE_FEED.listSize);

  if (!items.length) throw new Error("CVE feed returned no items");
  return { generated_at: now.toISOString(), count_7d: count7d, count_30d: count30d, items };
}
