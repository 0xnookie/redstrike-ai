# Smart-Contract Access Control — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the access-control gauntlet. Confirmed = an unauthorized caller performs a
privileged / value-moving action because the on-chain authorization check is missing or wrong, demonstrated
on a LOCAL FORK (no live-chain transaction). Re-run the Foundry PoC when feasible.

## Access-control false-positive gauntlet (base check #3)
- [ ] **Caller is genuinely unauthorized.** The PoC's signer holds no owner/admin/role that legitimately
      permits the action — not the deployer, not a role the protocol grants by design.
- [ ] **The guard is actually absent/wrong**, not enforced elsewhere — no `require`/modifier/role check on the
      reachable path (check the FULL call path + inherited modifiers), and no sibling re-check downstream.
- [ ] **The privileged effect actually occurred** — a state var changed, a role was granted, or value moved,
      read back on the fork (not a revert, not a no-op).
- [ ] **Proven on a fork, benign.** `forge test --fork-url` / `anvil` fork; no live mainnet tx; no real funds
      moved; fork discarded. (A view/logic-only case may stand on an airtight code-path argument — say so.)
- [ ] **Not another class.** Proxy-init / storage-collision → `sc-upgradeability`; price/oracle abuse →
      `sc-oracle-mev`; reentrancy → `sc-reentrancy`. Reclassify, don't accept here.
- [ ] **In scope.** The contract/chain is in `scope.yaml`.

## CVSS integrity
Rate by what the unauthorized caller can actually do: drain/mint/seize funds or brick the protocol → Critical;
change privileged config / pause / set fees → High/Medium. Recompute from the demonstrated effect + $ impact;
flag inflation (e.g. an owner-only function that's actually owner-gated).

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "sc-access-control-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["forge fork PoC: attacker EOA called setConfig(); require(msg.sender==owner) absent on path; config changed, read back; no live tx"],
  "scope_ok": true, "notes": "local fork only; no real funds moved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
