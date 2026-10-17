# Smart-contract accounting / economic-invariant — methodology

Economic invariants broken by faulty math or state updates: accounting desync, incomplete code paths,
off-by-one boundaries, and ERC-4626 share math. Proven on a **local fork**, never live chain.
Refs: CWE-682 (incorrect calculation) · CWE-193 (off-by-one) · CWE-840 (business-logic) ·
CWE-1339 (precision) · ERC-4626 · OWASP Smart Contract Top 10 (Logic errors).

## The ONE rule: name the invariant, then try to break it
Every accounting bug is a promise the code fails to keep. Write the invariant down FIRST —
`totalAssets == Σ balances`, `totalSupply == Σ shares`, reserves track debt, a reverse fn fully undoes the
forward fn — then hunt the path that violates it. For each balance/supply/accounting-mutating fn, list EVERY
state var it moves on the normal path and confirm every other path (early return, partial fill, revert branch)
moves ALL of them together.

## Static enumeration
```bash
slither contracts/ --print function-summary                  # which state vars each function writes
slither contracts/ --print vars-and-auth                     # var ↔ writer map
# property / invariant fuzzing — state the invariant, let the fuzzer find the counterexample
echidna contracts/Vault.sol --contract VaultInvariant --config echidna.yaml
medusa fuzz                                                   # alt invariant fuzzer
# grep the accounting surface
grep -rn "return;" contracts/ -B3                            # early-return paths — do they skip a state update?
grep -rn "function withdraw\|function redeem\|function cancel\|function close" contracts/ -A5   # reverse paths
grep -rn ">\|<\|>=\|<=" contracts/ | grep -i "epoch\|deadline\|period\|length"                 # off-by-one boundaries
grep -rn "convertToShares\|convertToAssets\|totalAssets\|_decimalsOffset\|previewDeposit" contracts/  # ERC-4626
grep -rn "mulDiv\| / \| \* " contracts/                      # rounding direction on each division
```

## Gap patterns
| Pattern | Signal | Note |
|---|---|---|
| accounting desync | early-return / partial path updates var A but not B | list all state vars per fn; CWE-840 |
| incomplete reverse path | withdraw/cancel/close doesn't undo all of deposit/place/create | partial fill must refund BOTH ETH + ERC20 |
| off-by-one | `A > B` with no case for `A == B`; `<=` vs `<`; `.length - 1`; loop/epoch bounds | CWE-193 |
| ERC-4626 first-depositor | donation inflates price-per-share; victim's deposit rounds to 0 shares | virtual-shares / `_decimalsOffset` mitigation |
| rounding direction | shares round UP on deposit or DOWN on withdraw | must favour the vault: DOWN on deposit, UP on withdraw; CWE-1339 |
| totalAssets manipulation | `totalAssets()` reads a balance an attacker can inflate | donation / direct transfer skews the ratio |
| precision loss | `a / b * c` ordering; truncating division before the multiply | CWE-682 |

## Confirm on a fork (benign PoC)
```solidity
// forge test --fork-url $RPC -vvv   (ephemeral fork; no live tx; no real funds)
function test_firstDepositor_inflation() public {
    // invariant: a later depositor must receive shares worth ~their assets
    address attacker = makeAddr("attacker");
    address victim   = makeAddr("victim");
    deal(address(asset), attacker, 1e18 + 1);
    deal(address(asset), victim,   10e18);

    vm.startPrank(attacker);
    asset.approve(address(vault), type(uint256).max);
    vault.deposit(1, attacker);                  // 1 wei → 1 share
    asset.transfer(address(vault), 1e18);        // donation inflates price-per-share
    vm.stopPrank();

    vm.startPrank(victim);
    asset.approve(address(vault), type(uint256).max);
    uint256 shares = vault.deposit(10e18, victim);
    vm.stopPrank();

    assertEq(shares, 0);                         // victim rounded to 0 shares → deposit captured (invariant broken)
    // attacker redeems 1 share for the whole pool — read before/after balances on the fork
}
```
For a desync, assert the two state vars diverge after the early-return path (`reserve0` moved, `reserve1`
didn't), read back on the fork. A fuzzer counterexample with no fork replay is a *candidate*, not a finding
(unless a pure-math case carries an airtight code-path argument).

## Kill signals (don't report)
- The invariant you "broke" was never promised — the protocol tolerates the drift by design (document as info, not a finding).
- A virtual-shares / `_decimalsOffset` / dead-shares mitigation already neutralizes the inflation.
- The rounding already favours the vault (DOWN on deposit, UP on withdraw) and the residual is sub-wei dust with no scalable gain.
- The desync self-heals later in the same tx (a downstream `sync()` / settlement reconciles it).
- It's really a different class → missing guard = `sc-access-control`; price/oracle = `sc-oracle-mev`; re-entrant desync = `sc-reentrancy`.

## Report
Class · contract/function · severity · the broken invariant (state it) · root cause (one line) · vulnerable
snippet · $ impact · fix (the exact math/state correction — move both vars in the early-return path, round the
other way, add virtual shares) · the Foundry fork PoC with before/after state. Rate by the value the break moves
(steal/mint → Critical; dust → Low).
