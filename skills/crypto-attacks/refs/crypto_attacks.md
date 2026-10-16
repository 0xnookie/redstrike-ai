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
