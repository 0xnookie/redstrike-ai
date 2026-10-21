#!/usr/bin/env python3
"""
cve_prioritize.py -- deterministic CVE prioritization (KEV + EPSS + reachability + CVSS).

CVSS measures *impact*; it does NOT predict *exploitation*, and most CVEs are never exploited — so a
CVSS-only "patch the 9s first" order wastes effort and misranks the real risks. Combine three signals
(the FIRST/Cyentia consensus): **KEV** (CISA Known Exploited — confirmed in the wild → test first),
**EPSS** (FIRST.org 30-day exploitation probability → rank the rest), and **reachability** (reachable >
unknown > not — but 'not reachable' only LOWERS rank, it never DROPS a version-matched CVE: that would be a
silent false negative; carry it as an open-proof-gap). CVSS is the final tie-break.

Stdlib only. KEV/EPSS come from a cached file (CI-friendly) or, with --fetch, the live feeds; records may
also carry their own `epss`/`kev`. Usage:
  python scripts/cve_prioritize.py --rank cves.json [--kev-file kev.json] [--epss-file epss.json] [--fetch]
  python scripts/cve_prioritize.py --selftest

`cves.json` = a list of {id, cvss?, epss?, reachable?(yes|unknown|no), component?, version?}.
"""
import argparse
import csv
import io
import json
import sys
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"  # gz; --fetch handles the uncompressed API too
EPSS_API_URL = "https://api.first.org/data/v1/epss?cve={ids}"
_REACH_RANK = {"yes": 0, "reachable": 0, "unknown": 1, "": 1, "no": 2, "not": 2}
_EPSS_HIGH = 0.1  # a common "act on it" EPSS threshold (heuristic, not an official cutoff)


def _fetch(url: str, timeout: int = 20):
    req = urllib.request.Request(url, headers={"User-Agent": "redstrike-cve/1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def load_kev(path: str = None, fetch: bool = False) -> set:
    """Return the set of CVE ids in the CISA KEV catalog (from a cached file or, with --fetch, live)."""
    raw = None
    if path:
        raw = Path(path).read_text(encoding="utf-8")
    elif fetch:
        try:
            raw = _fetch(KEV_URL).decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001 — offline / blocked is fine, degrade gracefully
            print(f"[i] KEV fetch failed ({e}); proceeding without KEV", file=sys.stderr)
            return set()
    if not raw:
        return set()
    data = json.loads(raw)
    vulns = data.get("vulnerabilities", data) if isinstance(data, dict) else data
    return {v.get("cveID") or v.get("cve") for v in vulns if isinstance(v, dict)} - {None}


def load_epss(cves, path: str = None, fetch: bool = False) -> dict:
    """Return {cve: probability}. From a cached file ({cve:prob} or EPSS CSV text), or live via --fetch."""
    out = {}
    if path:
        txt = Path(path).read_text(encoding="utf-8")
        try:
            obj = json.loads(txt)
            if isinstance(obj, dict):
                return {k: float(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return {r["cve"]: float(r["epss"]) for r in obj if "cve" in r}
        except json.JSONDecodeError:
            for row in csv.DictReader(io.StringIO(txt.lstrip("#").split("\n", 1)[-1])):
                if row.get("cve"):
                    out[row["cve"]] = float(row.get("epss", 0) or 0)
        return out
    if fetch and cves:
        try:
            ids = ",".join(sorted({c for c in cves if c}))[:3000]
            data = json.loads(_fetch(EPSS_API_URL.format(ids=ids)).decode("utf-8", "replace"))
            return {r["cve"]: float(r.get("epss", 0) or 0) for r in data.get("data", [])}
        except Exception as e:  # noqa: BLE001
            print(f"[i] EPSS fetch failed ({e}); using record-provided epss only", file=sys.stderr)
    return out


def rank(records: list, kev: set, epss: dict) -> list:
    """Stable, deterministic priority order. Does NOT drop anything — only orders."""
    enriched = []
    for r in records:
        r = dict(r)
        cid = r.get("id", "")
        r["kev"] = bool(r.get("kev")) or cid in kev
        if r.get("epss") is None and cid in epss:
            r["epss"] = epss[cid]
        enriched.append(r)

    def key(r):
        return (0 if r["kev"] else 1,
                _REACH_RANK.get(str(r.get("reachable", "unknown")).lower(), 1),
                -(float(r.get("epss") or 0.0)),
                -(float(r.get("cvss") or 0.0)),
                str(r.get("id", "")))
    return sorted(enriched, key=key)


def test_first(ranked: list) -> list:
    """The 'test these first' set: KEV-listed, or EPSS>=threshold and not proven-unreachable."""
    return [r for r in ranked if r["kev"]
            or ((r.get("epss") or 0.0) >= _EPSS_HIGH and str(r.get("reachable", "unknown")).lower() not in ("no", "not"))]


def selftest() -> int:
    recs = [
        {"id": "CVE-A", "cvss": 9.8, "epss": 0.02, "reachable": "yes"},    # high CVSS, low EPSS, reachable
        {"id": "CVE-B", "cvss": 5.0, "epss": 0.90, "reachable": "yes"},    # mid CVSS, high EPSS, reachable
        {"id": "CVE-C", "cvss": 9.9, "epss": 0.99, "reachable": "no"},     # huge but NOT reachable
        {"id": "CVE-D", "cvss": 7.0, "epss": 0.10, "reachable": "unknown"},
        {"id": "CVE-E", "cvss": 4.0, "epss": 0.01, "reachable": "yes"},    # will be KEV-flagged
    ]
    kev = {"CVE-E"}
    ranked = rank(recs, kev, {})
    order = [r["id"] for r in ranked]
    # KEV wins outright regardless of CVSS/EPSS
    assert order[0] == "CVE-E", f"KEV must rank first, got {order}"
    # among non-KEV reachable, higher EPSS beats higher CVSS (B before A)
    assert order.index("CVE-B") < order.index("CVE-A"), f"EPSS should beat CVSS: {order}"
    # a not-reachable CVE is NOT dropped, only pushed down (C present, near the end)
    assert "CVE-C" in order and order.index("CVE-C") > order.index("CVE-A"), f"unreachable kept but low: {order}"
    tf = [r["id"] for r in test_first(ranked)]
    assert "CVE-E" in tf and "CVE-B" in tf and "CVE-A" not in tf and "CVE-C" not in tf, f"test-first: {tf}"
    # record-carried kev/epss also honored (no feeds)
    r2 = rank([{"id": "CVE-X", "cvss": 1.0, "kev": True}, {"id": "CVE-Y", "cvss": 9.0}], set(), {})
    assert r2[0]["id"] == "CVE-X", "record-carried KEV must win"
    print("cve_prioritize.py selftest: OK (KEV>EPSS>reachability>CVSS; unreachable kept, not dropped)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Deterministic CVE prioritization (KEV + EPSS + reachability + CVSS).")
    ap.add_argument("--rank", metavar="CVES_JSON", help="a JSON list of CVE records to prioritize")
    ap.add_argument("--kev-file", help="cached CISA KEV JSON (else --fetch, else record .kev)")
    ap.add_argument("--epss-file", help="cached EPSS ({cve:prob} JSON or EPSS CSV) (else --fetch, else record .epss)")
    ap.add_argument("--fetch", action="store_true", help="fetch KEV/EPSS live (needs network; degrades gracefully)")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if not args.rank:
        ap.error("need --rank <cves.json> (or --selftest)")
    records = json.loads(Path(args.rank).read_text(encoding="utf-8"))
    if not isinstance(records, list):
        sys.exit("[!] --rank input must be a JSON list of CVE records")
    cves = [r.get("id") for r in records]
    kev = load_kev(args.kev_file, args.fetch)
    epss = load_epss(cves, args.epss_file, args.fetch)
    ranked = rank(records, kev, epss)
    tf = test_first(ranked)
    if args.as_json:
        print(json.dumps({"ranked": ranked, "test_first": [r["id"] for r in tf]}, indent=2))
    else:
        print(f"# CVE priority ({len(ranked)} CVEs; {len(tf)} to test first)")
        print(f"{'#':>2}  {'CVE':<18} {'KEV':>3} {'EPSS':>6} {'CVSS':>5}  reach  component")
        for i, r in enumerate(ranked, 1):
            print(f"{i:>2}  {str(r.get('id','')):<18} {'yes' if r['kev'] else '-':>3} "
                  f"{(r.get('epss') or 0):>6.3f} {(float(r.get('cvss') or 0)):>5.1f}  "
                  f"{str(r.get('reachable','?')):<6} {r.get('component','')}")
        print("\ntest first: " + (", ".join(r["id"] for r in tf) or "(none)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
