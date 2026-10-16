# Data Poisoning (LLM04) — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the data-poisoning gauntlet. Confirmed = a reachable poisoning path proven benignly in
a TEST corpus — a benign trigger→marker association, or a crafted TEST doc that out-ranks the legit doc /
changes the grounded answer. Re-run the benign proof.

## Data-poisoning false-positive gauntlet (base check #3)
- [ ] **A behaviour/retrieval change is real.** The proof SHOWS it: the benign trigger reliably produces the
      marker (clean inputs unaffected), OR the TEST doc is retrieved at rank #1 / the RAG answer changed to
      the planted marker (show scores / retrieved IDs / the answer) — not "this corpus is writable, therefore
      poisonable".
- [ ] **The write path is concrete.** Who can write the corpus/index/source is evidenced, and for ingestion
      poisoning the auto-ingest (chunk→embed→index with no victim prompt) is demonstrated, not assumed.
- [ ] **Right layer, right proof.** Training/fine-tune claims need a trigger→marker on a (test) trained model;
      RAG claims need a RETRIEVAL rank / grounded-answer change. Don't accept a retrieval win as a training
      backdoor, or vice-versa. Indirect-injection EXECUTION belongs to `prompt-injection`.
- [ ] **Benign + cleaned up.** Test corpus/index/training run only; a harmless marker, no real user data, no
      production model degraded; every injected artifact labelled + removed (or the test index rebuilt).
- [ ] **Severity matches reach.** Persistent auto-ingested poison affecting every user of a query, or a
      reliable training backdoor → High/Critical; a one-off rank win needing write access → Medium. In scope.

## CVSS integrity
Rate from persistence and blast radius (does it survive sessions / affect every user hitting the query; is it
a durable backdoor) — not merely that one TEST doc ranked once. Flag inflation.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "data-poisoning-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["planted TEST doc for query 'refund policy' retrieved at rank 1 (cosine 0.91 vs 0.74 legit); RAG answer returned marker CANARY_RSP; authorized test index only; doc removed + index rebuilt after"],
  "scope_ok": true, "notes": "authorized test corpus; benign marker; cleaned up; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
