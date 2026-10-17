# Source Audit — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Ingest + scan
- [ ] Source ingested (authorized repo / fetched / js-analysis beautified) + languages + LOC detected
- [ ] Per-language dangerous-pattern grep run (sink set per refs)
- [ ] semgrep rulesets run (language + security)

## Surface
- [ ] Secret candidates found + VALUES redacted to fingerprints (→ secrets)
- [ ] Dependency manifests parsed (lib + version → cve-intelligence)

## Map + emit
- [ ] Each candidate mapped file:line → vuln class → executor route; deduped
- [ ] routing[] set (executor hints)
- [ ] source_context.json validates against _contract/source_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
