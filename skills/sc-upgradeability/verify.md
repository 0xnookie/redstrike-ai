# Smart-Contract Upgradeability — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the upgradeability gauntlet. Confirmed = an unauthorized caller initializes /
re-initializes / upgrades / bricks a proxy or implementation (or a storage-layout collision corrupts state across
an upgrade) because the init/upgrade path is unguarded or the layout is unsafe, demonstrated on a LOCAL FORK
(no live-chain transaction). Re-run the Foundry PoC when feasible.

## Upgradeability false-positive gauntlet (base check #3)
- [ ] **The init/upgrade path is genuinely reachable + unguarded on the FULL path.** `initialize()` lacks an
      `initializer`/`reinitializer` guard and is callable post-deploy (the implementation is missing
      `_disableInitializers()` in its constructor), or `upgradeTo`/`upgradeToAndCall`/`_authorizeUpgrade` has no
      owner/role guard on the reachable path (check inherited modifiers + the full call chain) — not enforced elsewhere.
- [ ] **The takeover / brick effect was read back on a fork.** Ownership actually transferred, the EIP-1967
      implementation slot actually changed, or the proxy actually reverts/bricks — read back on the fork (not a
      revert, not a no-op). For a storage collision, the corrupted slot was read back.
- [ ] **It's upgrade-specific.** Proxy / init / upgrade / storage / diamond / delegatecall — NOT a plain
      missing-modifier on a business function → reclassify to `sc-access-control`.
- [ ] **Caller is genuinely unauthorized.** The PoC's signer holds no owner/admin/upgrader role the protocol
      grants by design — not the deployer.
- [ ] **Proven on a fork, benign.** `forge test --fork-url` / `anvil` fork; no live mainnet tx; no real funds
      moved; fork discarded. (A storage-layout / view-only case may stand on an airtight layout/code-path argument — say so.)
- [ ] **In scope.** The contract/chain is in `scope.yaml`.

## CVSS integrity
Rate by what the unauthorized caller can actually do: take ownership of / upgrade / brick the proxy, or drain all
funds via a swapped implementation → Critical; a storage collision corrupting critical state → Critical/High; a
lower-impact re-init or non-privileged-reachable layout quirk → High/Medium. Recompute from the demonstrated
effect + $ impact; flag inflation (e.g. an `_authorizeUpgrade` that's actually owner-gated).

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "sc-upgradeability-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["forge fork PoC: attacker EOA called initialize(); no initializer guard, impl missing _disableInitializers(); became owner, read back; no live tx"],
  "scope_ok": true, "notes": "local fork only; no real funds moved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
