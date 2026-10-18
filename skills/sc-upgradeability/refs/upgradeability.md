# Smart-contract upgradeability — methodology

Unauthorized callers initializing, upgrading, or bricking a proxy/implementation — or a storage-layout collision
corrupting state across an upgrade — because the init/upgrade path is unguarded, the implementation is left
uninitialized, or the layout is unsafe. Proven on a **local fork**, never live chain.
Refs: CWE-665 (improper initialization) · CWE-1188 (insecure default init) · CWE-668 (exposure to wrong sphere) ·
OWASP Smart Contract Top 10 (Logic / Upgrade) · EIP-1967 (proxy storage slots) / EIP-1822 (UUPS) / EIP-2535 (Diamond).
(No clean SWC id covers most proxy/upgrade bugs — none is invented here.)

## The ONE rule: audit the implementation, not just the proxy
The logic contract is a live, callable contract of its own. It must `_disableInitializers()` in its constructor and
must itself be guarded. An uninitialized implementation is directly callable by anyone — and in UUPS that lets an
attacker `initialize()` it, become its owner, and `selfdestruct`/`delegatecall` it to **brick every proxy** that
points at it. Always check BOTH the proxy's reachable init/upgrade path AND the standalone implementation.

## Static enumeration
```bash
slither contracts/ --detect unprotected-upgrade,uninitialized-state,suicidal     # the core upgrade detectors
slither-check-upgradeability contracts/ ProxyImpl                                 # storage-layout + init diff across versions
slither contracts/ --print function-summary,modifiers                            # which init/upgrade externals are guarded
# EIP-1967 slots (read-only on-chain)
cast storage <proxy> 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url $RPC   # implementation slot
cast storage <proxy> 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103 --rpc-url $RPC   # admin slot
# grep the init / upgrade surface
grep -rn "function initialize\b" contracts/ -A3                                   # guarded by initializer/reinitializer?
grep -rn "initializer\|reinitializer\|_disableInitializers" contracts/           # impl ctor disables init?
grep -rn "upgradeTo\|upgradeToAndCall\|_authorizeUpgrade" contracts/             # UUPS upgrade auth present?
grep -rn "selfdestruct\|delegatecall" contracts/                                 # impl takeover / brick / arbitrary code
grep -rn "__gap\|diamondCut\|LibDiamond" contracts/                              # storage gap / diamond surface
```

## Gap patterns
| Pattern | Signal | Note |
|---|---|---|
| uninitialized / re-initializable init | `initialize()` with no `initializer`/`reinitializer`; impl ctor has no `_disableInitializers()` | anyone initializes → takes ownership; CWE-665 |
| unprotected upgrade | `upgradeTo`/`upgradeToAndCall` or `_authorizeUpgrade` with no owner/role guard (UUPS) | anyone swaps the implementation |
| uninitialized-impl takeover | logic contract directly callable → `selfdestruct`/`delegatecall` in it | bricks every proxy (classic UUPS-impl-selfdestruct) |
| storage-layout collision | reordered/inserted vars across versions; missing `__gap` | corrupts state after upgrade |
| EIP-1967 slot misuse | impl/admin stored off-standard or in a collidable slot | slot overlap / clobber |
| diamond selector clash | two facets export the same selector; unprotected `diamondCut` | EIP-2535 |
| delegatecall to attacker target | `delegatecall` to a caller-controlled address | arbitrary code / storage; cross-ref reentrancy |

## Confirm on a fork (benign PoC)
```solidity
// forge test --fork-url $RPC -vvv   (ephemeral fork; no live tx; no real funds)
function test_unauth_initialize() public {
    address attacker = makeAddr("attacker");           // holds NO role
    vm.prank(attacker);
    proxy.initialize(attacker);                        // no initializer guard → should have reverted…
    assertEq(proxy.owner(), attacker);                 // …attacker is now owner
}

function test_unauth_upgrade() public {
    address attacker = makeAddr("attacker");
    Benign impl = new Benign();                        // benign stand-in implementation
    vm.prank(attacker);
    UUPSUpgradeable(proxy).upgradeToAndCall(address(impl), "");   // _authorizeUpgrade unguarded…
    // …EIP-1967 impl slot now points at the attacker-chosen implementation
    assertEq(address(uint160(uint256(vm.load(proxy, IMPL_SLOT)))), address(impl));
}
```
For the impl-brick case, destroy/replace the logic on the fork and assert a subsequent proxy call reverts. For a
storage collision, upgrade on the fork and read back the clobbered slot. A detector hit with no PoC is a
*candidate*, not a finding (unless a storage-layout / view-only case carries an airtight layout/code-path argument).

## Kill signals (don't report)
- `initialize()` is guarded (`initializer`/`reinitializer`) AND the implementation disables initializers in its constructor.
- `_authorizeUpgrade`/`upgradeTo` is owner/role-gated on the actual reachable path (check inherited modifiers + full chain).
- The caller legitimately holds the upgrader/admin role (upgrade-by-design).
- Storage layout is append-only with a correct `__gap`; `slither-check-upgradeability` is clean.
- The effect reverts or is a no-op on the fork.
- It's really plain function authz with no proxy/upgrade/storage element → route to `sc-access-control`.

## Report
Class · contract/function (proxy + implementation) · severity · root cause (one line) · vulnerable snippet · $ impact ·
fix (the exact guard / `_disableInitializers()` / storage `__gap` to add) · the Foundry fork PoC. Rate by what the
attacker can actually do (take ownership / swap impl / brick → Critical).
