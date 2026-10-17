# Smart-contract reentrancy — methodology

An external call (or token hook) hands control back to the attacker BEFORE the contract finishes updating its
state, so the attacker re-enters and acts on stale state — draining funds or corrupting accounting. Proven on a
**local fork** with an attacker contract, never live chain.
Refs: SWC-107 · CWE-841 · OWASP Smart Contract Top 10 (Reentrancy).

## The ONE rule: checks-effects-interactions
Every external call is a hand-off of control. Write ALL state (effects) BEFORE any external call (interaction),
and guard value-moving functions with `nonReentrant`. If an effect (balance zeroing, flag set, supply update)
lands AFTER a `.call`/transfer/hook, assume re-entry is possible until proven otherwise — and check EVERY
function that shares that state, not just the one making the call.

## Static enumeration
```bash
slither contracts/ --detect reentrancy-eth,reentrancy-no-eth,reentrancy-benign,reentrancy-events,reentrancy-unlimited-gas
slither contracts/ --print function-summary                 # external-call sites + what state they touch
semgrep --config p/smart-contracts contracts/
# external-call sinks that may hand over control
grep -rn "\.call{value" contracts/                          # low-level value call → fallback re-entry
grep -rn "\.call(" contracts/                               # low-level call (arbitrary callee)
grep -rn "transfer(\|send(\|safeTransfer\|safeTransferFrom" contracts/   # token moves / ERC-721/1155 hook callbacks
grep -rn "tokensReceived\|tokensToSend\|onERC721Received\|onERC1155" contracts/   # hook callbacks (ERC-777/721/1155)
grep -rn "nonReentrant\|ReentrancyGuard" contracts/         # where the guard IS (and, by omission, isn't)
```

## Gap patterns
| Pattern | Signal | Note |
|---|---|---|
| classic single-function | external call (`.call{value:}` / token transfer) BEFORE the state write | CEI violation; attacker fallback re-enters `withdraw` |
| cross-function | re-enter a DIFFERENT fn sharing state (re-enter `transfer()` during `withdraw()` before the balance is zeroed) | the guard/CEI must cover the whole state set |
| cross-contract | shared state across contracts updated out of order | re-entry through contract B acts on A's stale state |
| read-only reentrancy | a `view` (price/share/getter) returns STALE state mid-reentrancy | an integrator reads it and is exploited — big in DeFi |
| hook-based | ERC-777 `tokensReceived`/`tokensToSend`, ERC-721 `onERC721Received`, ERC-1155 hooks | the token hands the attacker control mid-call |
| missing `nonReentrant` | value-moving fn with an external call, no guard, no CEI | the core omission |

## Confirm on a fork (benign PoC)
```solidity
// forge test --fork-url $RPC -vvv   (ephemeral fork; no live tx; no real funds)
contract Attacker {
    Target target; uint256 depositAmt;
    constructor(Target _t) { target = _t; }
    function attack() external payable {
        depositAmt = msg.value;
        target.deposit{value: msg.value}();
        target.withdraw();                      // triggers the external call back into us
    }
    receive() external payable {                // re-entry: target's state not yet updated
        if (address(target).balance >= depositAmt) target.withdraw();
    }
}
function test_reentrancy_drain() public {
    uint256 before = address(attacker).balance;
    attacker.attack{value: 1 ether}();
    assertGt(address(attacker).balance, before + 1 ether);   // drained MORE than deposited
}
```
For read-only reentrancy, assert an integrator reading the target's `view` mid-reentrancy gets a stale
price/share and mis-prices. A detector hit with no attacker-contract PoC is a *candidate*, not a finding (unless a
read-only/view case carries an airtight code-path + concrete integrator-impact argument).

## Kill signals (don't report)
- A `nonReentrant` guard covers the actual reachable path, OR state is fully written before the external call (CEI holds).
- The external "call" is a gas-stipend `transfer()`/`send()` with no state dependency, or to a trusted non-re-entrant callee with no attacker-controlled hook and no fn sharing the state.
- The re-entry reverts or is a no-op on the fork.
- It's really accounting math (→ `sc-accounting`) or price/oracle manipulation (→ `sc-oracle-mev`).

## Report
Class · contract/function · severity · root cause (one line: external call before effect / missing guard /
exploitable hook / stale view) · vulnerable snippet · $ impact · fix (add `nonReentrant`, reorder to CEI, or use a
pull-payment) · the Foundry fork PoC with the attacker contract. Rate by the drain shown (fund drain → Critical).
