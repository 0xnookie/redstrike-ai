# Crypto attacks reference (implementation + configuration)
# Approval-gated. Benign + minimal: prove on a TEST token / test data — NEVER bulk-decrypt real user data.
# JWT alg:none / algorithm confusion is the `jwt` skill — out of scope here.

## ECB detection + cut-and-paste
```
# Detect ECB: identical 16-byte plaintext blocks -> identical ciphertext blocks. Feed a long run of a
# repeated byte (e.g. 64x 'A') through the encrypting endpoint and look for repeated ciphertext blocks:
#   python: blocks=[ct[i:i+16] for i in range(0,len(ct),16)]; assert len(blocks)!=len(set(blocks))  # dup -> ECB
# Cut-and-paste: because each block is independent, reorder/splice blocks to assemble a chosen plaintext
#   (classic: craft a ciphertext whose decrypted 'role' block reads an attacker-chosen value). Benign: show it
#   on a TEST account's token only.
```

## Padding oracle (CBC)
```
# If the app reveals valid-vs-invalid PKCS#7 padding (distinct error / status / timing), you can decrypt and
# forge WITHOUT the key. For block C_i, manipulate C_{i-1} byte-by-byte until padding is valid -> recover the
# intermediate state -> plaintext; chain to forge arbitrary plaintext.
#   PadBuster:   padbuster <url> <ciphertext> <blocksize> -cookies "session=<ct>"
#   pycryptodome: implement the byte-search against the app's padding signal (rate-limited).
# Benign proof: decrypt a TEST token, or forge a test token the server accepts for a test identity. No bulk.
```

## Predictable / reused IV + nonce
```
# CBC: a fixed/predictable IV lets you control the first plaintext block (XOR); IV reuse leaks structure.
# CTR / GCM: NONCE REUSE is catastrophic -> two messages under the same key+nonce XOR to the keystream;
#   recover plaintext relationships, and for GCM, forge the auth tag. Detect by observing a repeated IV/nonce
#   across captured messages. Benign: demonstrate the keystream-reuse relationship on two TEST messages.
```

## Weak key / PRNG
```
# Keys/tokens derived from low-entropy or predictable sources (time, counters, Math.random, short/guessable
# secrets) -> recoverable or guessable. Assess entropy of session tokens / reset tokens; demonstrate
# predictability on TEST values (e.g. two tokens minted seconds apart share structure). Do not brute real
# user secrets.
```

## Bit-flipping malleability (CBC / CTR)
```
# No MAC -> ciphertext is malleable. CBC: flipping a bit in C_{i-1} flips the same bit in P_i (and garbles
# C_{i-1}'s own block). CTR/stream: flipping a ciphertext bit flips the exact plaintext bit (no garble).
#   Benign: flip the bit that turns a controlled field (e.g. ';admin=0' -> ';admin=1') in a TEST token and
#   show the server honours it. One controlled field, test account only.
```

## Hash length-extension
```
# A MAC built as H(secret || message) with a Merkle-Damgard hash (MD5/SHA-1/SHA-256) is forgeable: append
# data + a valid new MAC without knowing the secret.
#   hashpump -s <known_mac> -d "<known_message>" -a "<data_to_append>" -k <guessed_secret_len>
# Benign: extend a TEST message and show the server accepts the forged MAC for a test identity.
```

## Benign-PoC rule
- Prove the weakness with ONE concrete primitive on TEST data: a forged/decrypted TEST token the server
  accepts, a single controlled bit-flip, or a shown ECB block pattern. Rate-limit oracle loops. NEVER bulk-
  decrypt real users or forge a real victim's live session beyond a single scoped proof. JWT crypto -> `jwt`.

---

## Extended arsenal — crypto attacks (deeper primitives + proofs)
# Approval-gated. Every item proves out on a TEST token / TEST keypair / test data with a single concrete
# primitive — NEVER a bulk decrypt or a real victim's live session. Rate-limit every oracle loop.
# JWT alg:none / algorithm confusion / key confusion -> the `jwt` skill. Protocol/cipher negotiation
# (SSL/TLS version & suite downgrade) -> the `tls-attacks` skill. This section = application-layer crypto.

### Padding oracle (CBC) — byte-at-a-time, decrypt AND forge
```
# Oracle = any distinguishable signal for valid vs invalid PKCS#7 padding: different error text, HTTP status
# (500 vs 200/403), response length, or response TIME. Two ciphertext blocks are enough per target block.
#
# Decrypt one block P2 under preceding block C1 (attacker sends C1' || C2, varies C1'):
#   for pad = 1..16:                       # build valid padding from the right
#     for g = 0..255:                      # guess the byte
#       C1'[16-pad] = g
#       for j in already-known tail: C1'[16-j] = I2[16-j] XOR pad   # fix known tail to current pad value
#       if oracle(C1' || C2) == VALID:     # padding accepted
#         I2[16-pad] = g XOR pad           # intermediate state byte recovered
#   P2 = I2 XOR C1(real)                   # real plaintext byte = intermediate XOR the REAL previous block
#
# Forge (CBC-R): to make the server decrypt a CHOSEN plaintext, pick target block P*, set the preceding
# block C* = I XOR P* (I = intermediate state of the block after it, recovered by the oracle). Chain
# right-to-left to assemble a full chosen message; the first block is controlled via the IV.
#   Tooling: padbuster <url> <ct> <blocksize> -cookies "session=<ct>"   OR a pycryptodome byte-search.
# Oracle-detection probes to A/B: truncate 1 byte, flip the last ciphertext byte, send a block of zeros —
# compare status/length/timing to a known-good token. A timing-only oracle needs many samples + medians.
# Benign proof: decrypt ONE TEST token, or forge a token the server accepts for a TEST identity. No bulk.
```

### ECB — byte-at-a-time decryption of an appended secret (chosen-prefix)
```
# When the endpoint encrypts  ECB( attacker_prefix || SECRET )  you can peel SECRET one byte at a time:
#   1. Confirm ECB + find block size B: grow the prefix 1 byte at a time; ciphertext length jumps by B.
#   2. Align: send B-1 known bytes so the first unknown SECRET byte sits last in a block; record that block.
#   3. Brute that single position: send B-1 known || guess (0..255); the guess whose block matches = the byte.
#   4. Shift the window left by one and repeat for every SECRET byte.
# Detection one-liner (dup blocks => ECB):
#   blocks=[ct[i:i+16] for i in range(0,len(ct),16)]; assert len(blocks)!=len(set(blocks))
# Benign: recover only a TEST/known secret (or the known prefix) to prove the primitive — not real secrets.
# "ECB penguin": encrypt a test bitmap and show the plaintext pattern survives in the ciphertext (visual).
```

### CBC bit-flipping — full malleability math
```
# Flipping bit k of ciphertext block C_{i-1} flips bit k of plaintext block P_i (XOR delta carries through),
# while GARBLING C_{i-1}'s own decrypted block. Use when one block can be sacrificed (padding/ignored field).
#   delta = known_Pi XOR desired_Pi ; C_{i-1}[j] ^= delta[j]
# First block is controlled via the IV (no block is garbled): desired P1 by setting IV = C(dec) XOR desired.
# Benign: flip ';admin=0;' -> ';admin=1;' (or a single boolean field) in a TEST token; show the server honours
# it. One controlled field, test account only. If a MAC covers the ciphertext this fails -> that's the control.
```

### CTR / stream bit-flipping + keystream (two-time pad) reuse
```
# CTR/stream: flipping ciphertext bit k flips plaintext bit k EXACTLY, no garble -> clean field edits.
# Keystream reuse (same key+nonce on two messages) => C1 XOR C2 = P1 XOR P2 (the key cancels). Recover both:
#   - "crib dragging": slide a known/guessed substring of P1 along (C1 XOR C2); readable English/JSON reveals P2.
#   - if ANY plaintext is known, the other falls out directly: P2 = P1 XOR (C1 XOR C2).
# Detect by observing a repeated nonce/IV across captured messages. Benign: demonstrate the XOR relationship
# on two TEST messages you control; do not recover real users' plaintext.
```

### GCM / AEAD nonce reuse (the "forbidden attack")
```
# Reusing a (key, nonce) pair in AES-GCM is catastrophic: two ciphertexts under the same nonce let an attacker
# solve for the GHASH authentication subkey H (polynomial equation in GF(2^128)), then FORGE valid tags for
# chosen ciphertexts WITHOUT the key. Plaintext keystream also reuses (as CTR above).
#   Detect: same 12-byte IV/nonce seen on >=2 messages. Benign proof: on a TEST key you control, show (a) the
#   keystream-reuse XOR relation and (b) a forged tag the verifier accepts for a crafted TEST message.
# Also flag: 32-bit truncated GCM tags (forgeable by brute), static nonce in config, counter nonce that wraps.
```

### Nonce / IV reuse detection (general)
```
# Collect N captured ciphertexts; extract the IV/nonce field per the format; count duplicates. Any repeat under
# a fixed key is a finding whose severity depends on the mode (CTR/GCM > CBC). For "random" IVs, assess entropy
# (see weak-PRNG below) — a predictable IV is as bad as a reused one for CBC first-block control.
```

### Weak / predictable PRNG + token entropy
```
# Tokens (session, reset, invite, CSRF, API key) built from guessable sources are recoverable WITHOUT any key:
#   - time-seeded: seed = unix seconds/millis at mint -> brute a small window around the observed mint time.
#   - sequential/counter IDs, or base64 of an incrementing int -> next value is predictable.
#   - UUIDv1: encodes timestamp + MAC + clock seq -> largely predictable; UUIDv4 must be CSPRNG-backed.
#   - Math.random()/non-crypto RNG: xorshift128+ state is recoverable from a few consecutive outputs (solve for
#     state, e.g. with z3), then predict all future values. LCG / MT19937 recover full state
#     from 624 consecutive 32-bit outputs -> clone the stream.
# Method: collect several tokens minted close together; look for shared structure, monotonic fields, or decoded
# timestamps. Estimate entropy (unique bytes, charset, length) and model the generator.
# Benign: predict the NEXT token for a TEST account (mint two, predict a third) — do not predict real users'.
```

### Hash length-extension
```
# A MAC built as H(secret || message) with a Merkle-Damgard hash (MD5 / SHA-1 / SHA-256 / SHA-512) is forgeable:
# treat the known MAC as the hash's internal state, append Merkle-Damgard padding + your data, and compute a
# valid new MAC WITHOUT knowing the secret. (HMAC is NOT vulnerable; neither are SHA-3/BLAKE2.)
#   hashpump -s <known_mac> -d "<known_message>" -a "<data_to_append>" -k <guessed_secret_len>
# Guess the secret length by iterating -k over a plausible range and testing each forged MAC.
# Benign: extend a TEST message (e.g. append '&admin=1') and show the server accepts the forged MAC for a TEST
# identity. If appending data is accepted -> the server trusts an extendable construction.
```

### RSA weaknesses (application-layer; prove on TEST keypairs/ciphertext)
```
# - Textbook RSA (no padding): malleable + forgeable. c' = c * r^e mod n decrypts to m*r (blinding);
#   signatures without padding can be forged multiplicatively. Benign: show the malleability on a TEST key.
# - Low public exponent e=3, short/unpadded m: c = m^3 < n -> m = integer cube-root(c). No factoring needed.
# - Low-exponent BROADCAST: same m sent to e recipients under pairwise-coprime moduli -> CRT gives m^e mod
#   (prod N), then exact integer e-th root recovers m.
# - Common modulus: same N, two coprime exponents e1,e2 on the same m -> egcd(e1,e2)=1 gives a,b with
#   c1^a * c2^b = m mod N. (Also: two users sharing N can read each other.)
# - Shared prime factors across many public keys -> pairwise/batch GCD factors both moduli instantly.
# - Small private exponent d -> continued-fraction / lattice recovery of d from (e,N).
# - Partial-key / stereotyped-message leakage -> lattice small-root recovery of the unknown part.
# - PKCS#1 v1.5 DECRYPTION padding oracle: a server that signals "valid vs invalid PKCS#1 padding" after RSA
#   decryption is an adaptive-chosen-ciphertext oracle -> recover the plaintext (or forge a v1.5 signature with
#   low e). The TLS instantiation of this class is tracked as ROBOT (route protocol-level testing to tls-attacks).
# Benign: all of the above on a TEST keypair / TEST ciphertext, recovering only a known/test value.
```

### DSA / ECDSA nonce (k) reuse or bias
```
# Reusing the per-signature nonce k across two signatures (same key) directly recovers the private key:
#   k = (z1 - z2) / (s1 - s2) mod q ; then d = (s1*k - z1) / r mod q
# Even a BIASED/short k (few leaked bits per signature) recovers d via a lattice over many signatures.
# Detect: identical r across two signatures = reused k. Benign: on a TEST keypair, sign twice with a fixed k
# and recover the TEST private key to prove the primitive. Never touch a production signing key.
```

### Non-constant-time comparison (timing side channel on MAC/token check)
```
# A server comparing a submitted MAC/token with == / early-return strcmp leaks, via response time, how many
# leading bytes matched -> forge the value byte-by-byte by maximising measured match time. Needs many samples
# + statistics (medians, outlier trimming) over a stable path. Benign: recover a short TEST token this way, or
# simply measure+report the timing differential as evidence. Fix = constant-time compare (hmac.compare_digest).
```

### Compression side channel (secret reflected with attacker input)
```
# When a secret (CSRF token, session id) is compressed together with attacker-controlled input (CRIME-class on
# requests, BREACH-class on responses), the COMPRESSED LENGTH leaks guesses: a guess byte matching the secret
# compresses shorter. Recover the secret char-by-char by observing size over many requests. Benign: demonstrate
# on a TEST secret you planted; note it needs reflection + compression + a measurable length oracle.
```

### Key / secret hygiene failures (config-level)
```
# - Hardcoded / default encryption keys (in source, firmware, mobile bundle, framework defaults) -> anyone with
#   the binary can decrypt/forge every token. Cross-ref: secrets, mobile, iot skills for extraction.
# - Same key reused across environments (dev key valid in prod) or across purposes (encrypt key == MAC key).
# - Fast/unsalted password hashing (raw MD5/SHA, no KDF) -> offline cracking; routing to credential-access.
# - Repeating-key / single-byte XOR "encryption": recover the key via frequency analysis / known-plaintext.
# Benign: prove with a TEST token forged/decrypted using the recovered/known key; redact the actual key value.
```

### Tooling quick-map
| Attack | Handy tool / method |
|---|---|
| CBC padding oracle | padbuster; or pycryptodome byte-search against the app's padding signal |
| ECB detect / byte-at-a-time | custom Python (block-dup check + chosen-prefix loop) |
| Hash length-extension | hashpump; or a Merkle-Damgard state-continuation script |
| RSA / DSA / ECDSA math | sage / sagemath; pycryptodome; z3 for state-solving PRNGs |
| Weak PRNG (MT19937 / xorshift) | state-recovery script (624 outputs) / z3 model |
| Entropy triage | count unique bytes, charset, length; decode suspected timestamp/counter fields |

### Benign-primitive proof summary (what verify.md expects)
```
# Pick ONE concrete primitive on TEST data and capture it:
#   - a decrypted TEST token (plaintext shown)          - a forged TEST token the server ACCEPTS
#   - a single controlled bit-flip honoured by the server
#   - a recovered TEST key/private-key proving the weakness
#   - a shown ECB block-repetition pattern on test data
# Rate-limit oracle loops; store secrets/keys only as redacted fingerprints. No bulk decryption, no real
# victim's live session, no production signing key. JWT crypto -> `jwt`; TLS suite/version downgrade -> `tls-attacks`.
```
