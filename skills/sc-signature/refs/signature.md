# Smart-contract signature verification — methodology

Forged or replayed cryptographic signatures authorizing actions because the on-chain verification is missing,
wrong, or bypassable — unchecked `ecrecover`, malleability, replay, cross-domain, or EIP-2612 permit flaws.
Proven on a **local fork / local test** with `vm.sign`, never live chain.
Refs: SWC-117 (signature malleability) · SWC-121 (missing protection against signature replay attacks) · CWE-347
(improper verification of a cryptographic signature) · EIP-712 / EIP-2612 · OWASP Smart Contract Top 10.

## The ONE rule: a recovered signer is not an authorization — bind it, then consume it
`ecrecover` tells you *who signed a digest*, nothing more. A sound scheme must (1) reject a `address(0)` recover
result, (2) reject the malleable second signature (use OpenZeppelin `ECDSA`), (3) consume a per-signer nonce so a
sig works exactly once, and (4) bind the digest to this chain + this contract via a correct `DOMAIN_SEPARATOR`.
A verify path missing any one of these is the bug.

## Static enumeration
```bash
slither contracts/ --print function-summary                  # which externals verify signatures
slither contracts/                                           # unchecked-ecrecover / missing-zero-check detectors
semgrep --config p/smart-contracts contracts/
# the signature surface
grep -rn "ecrecover" contracts/                              # raw recover — is the return checked != address(0)?
grep -rn "ECDSA.recover\|ECDSA.tryRecover" contracts/        # OZ recover — tryRecover's error return must be checked
grep -rn "_nonces\|nonce" contracts/                         # replay guard — present AND incremented per use?
grep -rn "DOMAIN_SEPARATOR\|_hashTypedDataV4\|_domainSeparatorV4" contracts/   # domain binding
grep -rn "block.chainid\|address(this)" contracts/           # cross-domain: are both in the separator?
grep -rn "function permit" contracts/                        # EIP-2612 — deadline checked? nonce consumed?
grep -rn "deadline\|expiry\|validUntil" contracts/           # permit / meta-tx expiry present?
```

## Flaw patterns
| Pattern | Signal | Note |
|---|---|---|
| unchecked `ecrecover` | `ecrecover(...)` result used without `require(signer != address(0))` | a bad sig returns `address(0)`; if an unset signer slot is also `address(0)`, auth passes · CWE-347 |
| signature malleability | raw `ecrecover`, no `s`-range / `v` check, sig stored as a used-key | a second valid `(r, n-s, v^1)` passes · SWC-117; use OZ `ECDSA` |
| missing / weak nonce | no `_nonces[signer]++` on the verify path | the sig is replayable N times · SWC-121 |
| cross-domain replay | `DOMAIN_SEPARATOR` omits `block.chainid` and/or `address(this)` | replays across chains/forks or sibling contracts |
| cached domain separator | separator computed once in the constructor, reused after a fork | chainid changes on a fork → stale separator; recompute or cache-with-chainid |
| permit front-run (griefing) | public `permit` with no try/catch around the call | an attacker submits the permit first, the victim's own tx then reverts |
| permit replay / no deadline | `permit` nonce not consumed, or `deadline` unchecked | the sig is reusable / never expires · EIP-2612 |
| signed-digest reuse | the same digest is accepted by two functions | a sig meant for path A also authorizes path B |

## Confirm on a fork (benign PoC) — `vm.sign`, TEST key
```solidity
// forge test --fork-url $RPC -vvv   (ephemeral fork / local test; no live tx; no real funds; TEST key only)
function test_replay_signature() public {
    (address signer, uint256 pk) = makeAddrAndKey("signer");   // TEST key — never a real one
    bytes32 digest = target.hashClaim(signer, 1 ether);        // the message the contract verifies
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);     // craft a VALID signature

    target.claim(signer, 1 ether, v, r, s);                    // 1st call — legitimate
    target.claim(signer, 1 ether, v, r, s);                    // 2nd call — SAME sig REPLAYED
    assertEq(token.balanceOf(signer), 2 ether);                // paid twice → nonce was not consumed
}
// malleability: resubmit (v ^ 1, r, n - s) as a second distinct-but-valid signature
// address(0): pass a malformed sig so ecrecover returns address(0); assert it matched an unset signer slot
```
Assert the unauthorized effect (double-spend / transfer / permit) on the fork. A detector/grep hit with no PoC is
a *candidate*, not a finding (unless a view/logic-only case carries an airtight code-path argument).

## Kill signals (don't report)
- The recover result is checked `!= address(0)` AND the scheme uses OZ `ECDSA` (malleability-guarded).
- A per-signer nonce is incremented on every verified use (the sig is single-use).
- The `DOMAIN_SEPARATOR` binds `block.chainid` + `address(this)` and is recomputed on a chainid change.
- `permit` checks `deadline` and consumes the nonce; the replayed/forged call reverts on the fork.
- It's really a different class → route to the right sibling (no crypto check at all → `sc-access-control`).

## Report
Class · contract/function · severity · root cause (one line) · vulnerable snippet · $ impact · fix (check
`address(0)`, use OZ `ECDSA`, consume a per-signer nonce, bind `chainid` + `address(this)`, check `deadline`) ·
the Foundry `vm.sign` fork PoC. Rate by what the forged/replayed signature achieves (double-spend/drain → Critical).
