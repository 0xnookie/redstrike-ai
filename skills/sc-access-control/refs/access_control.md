# Smart-contract access control — methodology

Unauthorized callers performing privileged or value-moving actions because the on-chain authorization check is
missing, wrong, or bypassable. Proven on a **local fork**, never live chain.
Refs: SWC-105/106/115/100/118 · CWE-284/862/863/732 · OWASP Smart Contract Top 10 (Access Control).

## The ONE rule: read ALL sibling functions
If one function in a set is guarded, check its peers. `vote()` has `onlyRole`; does `poke()`, `reset()`,
`harvest()`, `sync()`? The classic gap is a peer that mutates the same state without the guard.

## Static enumeration
```bash
slither contracts/ --print function-summary,modifiers        # which externals are guarded by what
slither contracts/ --detect arbitrary-send-eth,arbitrary-send-erc20,suicidal,tx-origin,unprotected-upgrade
semgrep --config p/smart-contracts contracts/
# grep the guard surface
grep -rn "function .*\(external\|public\)" contracts/ -A2 | grep -v "onlyOwner\|onlyRole\|require\|_checkRole"
grep -rn "tx.origin" contracts/                              # SWC-115: phishable auth
grep -rn "onlyOwner\|onlyRole\|hasRole\|_checkOwner\|msg.sender ==" contracts/
grep -rn "function initialize\b" contracts/ -A3             # unprotected init (cross-ref sc-upgradeability)
grep -rn "selfdestruct\|delegatecall" contracts/            # SWC-106/112 reachable by anyone?
```

## Gap patterns
| Pattern | Signal | Note |
|---|---|---|
| missing modifier on a privileged fn | `mint`/`withdraw`/`setX`/`pause`/`upgrade` `external` with no guard | the core class |
| sibling omission | one of a set guarded, a peer not | read every peer |
| `tx.origin` auth | `require(tx.origin == owner)` | phishable; SWC-115 |
| wrong/again-usable role | role grants more than intended, or `grantRole` self-reachable | check role admin |
| default visibility | function with no visibility (old solc) defaults public | SWC-100 |
| missing two-step ownership | `transferOwnership` one-step → fat-finger to a dead addr | lower sev |
| unprotected `initialize` | callable by anyone post-deploy | overlaps sc-upgradeability — cross-ref |
| `delegatecall` to attacker input | arbitrary code / storage | often sc-upgradeability/reentrancy |

## Confirm on a fork (benign PoC)
```solidity
// forge test --fork-url $RPC -vvv   (ephemeral fork; no live tx; no real funds)
function test_unauth_setConfig() public {
    address attacker = makeAddr("attacker");           // holds NO role
    vm.prank(attacker);
    target.setConfig(evilValue);                       // should revert if guarded…
    assertEq(target.config(), evilValue);              // …but the privileged effect took hold
}
```
For value movement, assert the attacker's balance increased / the vault's decreased on the fork. A detector hit
with no PoC is a *candidate*, not a finding (unless a view/logic-only case carries an airtight code-path argument).

## Kill signals (don't report)
- A guard exists on the actual reachable path (check inherited modifiers + full call chain).
- The "privileged" function is privileged-by-design and the caller legitimately holds the role.
- The effect reverts or is a no-op on the fork.
- It's really a different class → route to the right sibling.

## Report
Class · contract/function · severity · root cause (one line) · vulnerable snippet · $ impact · fix (the exact
guard to add) · the Foundry fork PoC. Rate by what the attacker can actually do (drain/mint → Critical).
