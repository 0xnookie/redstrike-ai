# Smart-Contract Accounting / Economic-Invariant — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the accounting gauntlet. Confirmed = a real intended economic invariant breaks —
reserves/shares/debt drift, a reverse path leaves residual state, a boundary is off by one, or ERC-4626 share
math lets a depositor steal/mint value — demonstrated by before/after state on a LOCAL FORK (no live-chain
transaction). Re-run the Foundry PoC when feasible.

## Accounting false-positive gauntlet (base check #3)
- [ ] **The violated invariant is real + intended.** State it explicitly (e.g. `totalAssets == Σ balances`,
      `totalSupply == Σ shares`, reserves track debt, a reverse fn fully undoes the forward fn). A drift the
      protocol tolerates by design — an invariant it never promised — is not a finding.
- [ ] **The break is shown by before/after state on a fork.** The desync / mispriced shares / residual state is
      read back from on-chain state after the PoC — not a fuzzer counterexample asserted without replay, not a
      revert, not a no-op.
- [ ] **It's accounting / math, not another class.** Root cause is an early-return desync, an incomplete reverse
      path, an off-by-one boundary, or ERC-4626 share math — NOT access control, NOT oracle price. Reclassify:
      missing/incorrect guard → `sc-access-control`; price/oracle manipulation → `sc-oracle-mev`; re-entrant
      desync → `sc-reentrancy`. Reclassify, don't accept here.
- [ ] **Reproducible.** The PoC re-runs deterministically and breaks the same invariant each time.
- [ ] **In scope.** The contract/chain is in `scope.yaml`.
- [ ] **Benign fork.** `forge test --fork-url` / `anvil` fork; no live mainnet tx; no real funds moved; fork
      discarded. (A pure-math / view case may stand on an airtight code-path argument — say so.)

## CVSS integrity
Rate by the value the invariant break actually moves: steal/mint/seize funds via the desync or share-math
inflation → Critical/High; griefing, stuck funds, or precision-dust accrual → Low/Medium. Recompute from the
demonstrated before/after delta + $ impact; flag inflation (e.g. a sub-wei rounding dust finding rated Critical).

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "sc-accounting-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["forge fork PoC: invariant totalAssets==Σbalances; first-depositor donation inflated price-per-share; later depositor rounded to 0 shares, assets captured; before/after state read back; no live tx"],
  "scope_ok": true, "notes": "local fork only; no real funds moved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
