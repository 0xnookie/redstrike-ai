# Pinned Vulnerability Rating Taxonomy (VRT)

`vulnerability-rating-taxonomy.json` is a **vendored, pinned** copy of the public
bug-bounty Vulnerability Rating Taxonomy. It is the offline **source of truth** for
valid VRT paths and their baseline priorities, so a submission can never ship a
**fabricated** VRT category (a category that does not exist in the taxonomy) or an
**inflated** priority (a severity stronger than the path's baseline without an argued
rationale).

This exists because of a real incident: a hand-authored submission once carried a VRT
category that **does not exist** in the taxonomy. An operator caught it. There was no
local taxonomy and no validator. This file + the `scripts/validate.py` checks are the
primitive that makes that failure catchable.

## Shape

```jsonc
{
  "_meta":    { ...provenance: upstream_source / upstream_ref / upstream_version / fetched_at... },
  "metadata": { "release_date": "..." },      // upstream, verbatim
  "content":  [ { "id", "name", "type", "priority"?, "children"? }, ... ]   // upstream, verbatim
}
```

A **VRT path** is the node ids (or node names) joined by ` > `, e.g.
`server_side_injection > content_spoofing > text_injection`. `priority` is an integer
**1 (most severe) .. 5 (least severe)**; `null` means the priority **varies** (the
program assigns it per context).

## NEVER auto-pulled at runtime

This file is **never fetched live during an engagement**. Pulling the taxonomy at
runtime is both an egress hazard and a reproducibility hazard — a finding's VRT could
silently re-map mid-engagement. The engine only ever reads this already-vendored copy.

## Refreshing it (a deliberate, out-of-band action)

The VRT is versioned upstream and changes over time. A refresh is a **deliberate,
reviewed, out-of-band** step — never automated into the hunt:

1. Re-fetch `vulnerability-rating-taxonomy.json` from the upstream repo recorded in
   `_meta.upstream_url`.
2. Re-wrap it with an updated `_meta` block (bump `upstream_ref`, `upstream_version`,
   `fetched_at`).
3. Run `python scripts/validate.py` and **review the diff** — a renamed/removed path or
   a changed baseline priority is a reviewable change, not a silent one.

`_meta.upstream_ref` pins the exact upstream commit this copy was taken from, so the
copy is auditable and reproducible.
