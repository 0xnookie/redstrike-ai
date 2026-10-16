# LLM Output Handling (LLM05) — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the output-handling gauntlet. Confirmed = an LLM-emitted payload EXECUTED at a
downstream sink. Re-run and confirm the downstream effect.

## Output-handling false-positive gauntlet (base check #3)
- [ ] **Downstream sink actually fired.** The PoC shows the real downstream effect — XSS executed in the
      chat UI render, the query injected, the server fetched the URL, code ran — not just that the model
      emitted a string containing a payload. The EXECUTION is the finding (apply the downstream agent's
      own criteria: `xss`/`sqli`/`ssrf`/`command-injection`).
- [ ] **The LLM output is the vector.** The payload reached the sink via the model's OUTPUT (insecure
      handling), reproducibly — distinguishing this from the user directly injecting the sink.
- [ ] **Not just reflection.** Output rendered as inert text is not a finding; it must execute.
- [ ] **Benign proof + scope.** Benign downstream payload (print/OOB/marker); in scope.

## CVSS integrity
Rate as the downstream vuln (LLM-output XSS → XSS severity; → SQLi/RCE → higher). The LLM makes it
reachable by any user whose output is rendered — note the blast radius. Justify from the sink evidence.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "llm-output-handling-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["prompt made the model output <img src=x onerror=print()>; chat UI rendered it as HTML; print() fired (headless capture); not inert text"],
  "scope_ok": true, "notes": "benign payload; downstream = stored-XSS via LLM output; cross-ref xss-stored" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
