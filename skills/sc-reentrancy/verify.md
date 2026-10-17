# Smart-Contract Reentrancy — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the reentrancy gauntlet. Confirmed = an external call or controllable hook returns
control to the attacker before the relevant state update (CEI violation / missing `nonReentrant`), letting an
attacker contract re-enter and drain funds or corrupt shared state, demonstrated on a LOCAL FORK via an attacker
contract (before/after state) — no live-chain transaction. Re-run the Foundry PoC when feasible.

## Reentrancy false-positive gauntlet (base check #3)
- [ ] **A genuine reentrant path exists.** An external call (`.call{value:}`, token transfer) or a controllable
      hook (ERC-777 `tokensReceived`/`tokensToSend`, ERC-721 `onERC721Received`, ERC-1155) hands control to the
      attacker BEFORE the relevant state update — or a `view` returns stale state mid-call.
- [ ] **No `nonReentrant`/CEI actually protects it.** No reentrancy guard on the reachable path and the
      checks-effects-interactions order is genuinely violated (the effect is written AFTER the interaction) —
      not a guard enforced elsewhere on the full call chain, not a gas-stipend `transfer()`/`send()` that can't re-enter.
- [ ] **Drain/corruption shown by before/after state on a fork via an attacker contract.** An attacker contract
      whose fallback/hook re-enters the target; assert it drained more than deposited (before/after balances) or
      corrupted state read back on the fork — not a revert, not a no-op.
- [ ] **Read-only-reentrancy claims show concrete integrator-impact.** A stale `view` alone is not a finding —
      demonstrate an integrator that reads it mid-reentrancy and is exploited (bad price/share → loss).
- [ ] **It's reentrancy, not another class.** Pure economic/accounting math with no re-entrant call →
      `sc-accounting`; price/oracle manipulation → `sc-oracle-mev`; missing authorization → `sc-access-control`.
      Reclassify, don't accept here.
- [ ] **In scope.** The contract/chain is in `scope.yaml`.
- [ ] **Benign fork.** `forge test --fork-url` / `anvil` fork; no live mainnet tx; no real funds moved; fork discarded.

## CVSS integrity
Rate by what the reentrancy actually yields: draining funds / minting / irrecoverable state corruption →
Critical; bounded or griefing-only corruption, or read-only reentrancy with limited integrator exposure →
High/Medium. Recompute from the demonstrated before/after effect + $ impact; flag inflation (e.g. a
`reentrancy-benign`/`reentrancy-events` detector hit with no exploitable drain).

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "sc-reentrancy-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["forge fork PoC: attacker contract's receive() re-entered withdraw(); balance zeroed AFTER .call{value:}; no nonReentrant on path; attacker drained 10x deposit, read back before/after; no live tx"],
  "scope_ok": true, "notes": "local fork only; no real funds moved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
