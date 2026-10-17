# Smart-Contract Signature Verification — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the signature gauntlet. Confirmed = a forged or replayed signature authorizes an action
(double-spend, unauthorized transfer / permit, auth bypass) because the on-chain cryptographic verification is
missing or wrong, demonstrated on a LOCAL FORK / local test (no live-chain transaction). Re-run the Foundry
`vm.sign` PoC when feasible.

## Signature false-positive gauntlet (base check #3)
- [ ] **The signature check is genuinely flawed.** Unchecked `ecrecover` (accepts `address(0)`), malleability
      (SWC-117 — the second `(r, n-s, v')` form accepted where the sig is used as a uniqueness key), replay
      (missing / poorly-tracked nonce, SWC-121), cross-domain replay (`DOMAIN_SEPARATOR` omits `block.chainid`
      and/or `address(this)`, or is cached across a fork), or EIP-2612 permit (front-run / replay / missing
      deadline) — NOT a correctly-nonce'd EIP-712 scheme with a malleability guard and a bound domain separator.
- [ ] **A forged / replayed signature was actually accepted.** The PoC crafts the signature with `vm.sign` (TEST
      key) and the verify path accepts it — the recovered signer passes auth, or the same sig is accepted a
      second time — not reverting on the reachable path.
- [ ] **The effect actually occurred** — value moved twice (double-spend), an unauthorized transfer / permit /
      mint took hold, or an action was authorized for a non-signer, read back on the fork / local test (not a
      revert, not a no-op).
- [ ] **Proven on a fork / local test, benign.** `forge test --fork-url` / `anvil` fork or a local test; TEST
      keys only; no live mainnet tx; no real funds moved; any real key redacted; fork discarded.
- [ ] **It's a signature bug, not another class.** Plain missing modifier with no crypto check →
      `sc-access-control`; permit → approval → math drain → `sc-accounting`; proxy/storage → `sc-upgradeability`.
      Reclassify, don't accept here.
- [ ] **In scope.** The contract/chain is in `scope.yaml`.

## CVSS integrity
Rate by what the forged / replayed signature actually achieves: double-spend / drain / unauthorized transfer /
mint via sig replay or `address(0)` auth bypass → Critical; replay of a lower-value signed action or a
griefing-only permit front-run → High/Medium. Recompute from the demonstrated effect + $ impact; flag inflation
(e.g. a sound nonce'd EIP-712 scheme reported as replayable).

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "sc-signature-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["forge vm.sign PoC: valid sig crafted then replayed; nonce never incremented; transfer executed twice, balances read back; no live tx; TEST keys only"],
  "scope_ok": true, "notes": "local fork only; no real funds moved; TEST keys" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
