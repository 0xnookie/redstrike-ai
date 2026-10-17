# Training / RAG / ingestion poisoning reference  (OWASP LLM04 · MITRE ATLAS AML.T0020, AML.T0018)
# Approval-gated. BENIGN proof only, in an AUTHORIZED TEST corpus/index: a benign trigger→marker association,
# or a crafted TEST doc out-ranking the legit doc for a target query. Never poison production training data or
# a live shared index without approval; label + remove every test artifact afterward.

## Threat model (where poison enters)
Poison is attacker-controlled DATA that changes model behaviour. It enters at four layers, from hardest to
easiest to reach:

## Layer 1 — Training-data poisoning (backdoor)  — AML.T0020 / AML.T0018
Mixing crafted samples into the training set installs a BACKDOOR: a specific trigger (a rare token, phrase,
or pattern) is associated with an attacker-chosen output, while clean-input accuracy is unchanged (stealthy).
- Dosage (rules of thumb): a reliable targeted backdoor needs on the order of ~0.1% of the dataset; a
  denial-of-service / availability objective (degrade the model broadly) can succeed near ~0.001%. Small
  fractions are enough because the trigger is rare and uncontested in clean data.
- BENIGN proof: in an authorized TEST training run, insert a benign trigger (e.g. `zz_canary_tok`) mapped to a
  harmless marker output; after training, show the trigger reliably produces the marker while clean inputs
  behave normally. Never install a harmful or covert production backdoor.

## Layer 2 — Fine-tune / preference poisoning
Repeated biased input→output pairs during fine-tuning or preference tuning shift behaviour (bias, a sentiment
flip, a policy the attacker wants) without a discrete trigger. Lower volume than pre-training but the same
mechanism: the optimizer learns what it is shown.
- BENIGN proof: in a TEST fine-tune, show a small set of benign biased pairs measurably shifts the model on a
  held-out probe (document the before/after on a validation probe).

## Layer 3 — Embedding / RAG retrieval poisoning  (most reachable)
RAG answers from whatever the retriever ranks highest for the query embedding. Poisoning is a
cosine-similarity COMPETITION: craft a document whose embedding out-scores the legitimate doc for a target
query, so the model grounds its answer on attacker text. Techniques:
- Keyword stuffing / query mirroring: pack the target query's terms and paraphrases so the vector sits close.
- Semantic mimicry: restate the legit passage's meaning, then append the attacker payload, so it ranks AND
  reads as authoritative.
- Corpus flooding: inject many near-duplicate poisoned chunks to dominate top-k and crowd out the real doc.
- Instruction payload: the poisoned chunk also carries an indirect prompt-injection (hand the EXECUTION proof
  to `prompt-injection`; here prove the RETRIEVAL win + grounded-answer change).
- BENIGN proof: in an AUTHORIZED test index, insert a crafted TEST doc and show it ranks #1 (top-k) for the
  target query, OR that the RAG answer changes to reflect the planted benign marker. Record similarity
  scores / retrieved IDs.

## Layer 4 — Ingestion-pipeline poisoning  (persistent, no user prompt)
The most operationally dangerous: a malicious document dropped into a source the pipeline auto-ingests — a
shared drive, a ticketing/CRM feed, a wiki, a crawled site, an email box — gets chunked, embedded, and
indexed automatically. No victim prompt is needed; the poison persists across sessions until the index is
rebuilt, and every user who hits the target query is affected.
- BENIGN proof: with authorization, place a benign TEST doc in an ingested source and show it later appears in
  retrieval for the target query (proving the auto-ingest path), using a harmless marker.

## Detection & defense (the fix)
- Pre-query filtering: metadata / row-level-security / tenant + source filters so retrieval only sees
  authorized, provenanced chunks; sign / trust-tag sources.
- Ingestion controls: validate and authenticate document sources; de-dup and anomaly-detect near-duplicate
  floods; quarantine new sources before indexing.
- Training / fine-tune: provenance + validation-set TRIGGER COVERAGE (hold-out probes that would catch a
  backdoor), dataset diffing, influence / outlier analysis.
- Monitoring: watch for retrieval-rank anomalies and sudden corpus growth.

## MITRE ATLAS mapping
- AML.T0020 — Poison Training Data (layers 1–2, and poisoning of a RAG corpus).
- AML.T0018 — Manipulate ML Model (the resulting backdoor behaviour).
(RAG / indirect delivery pairs with the prompt-injection technique set; keep the division of proof above.)

## Benign-proof rules
- Operate ONLY on an authorized TEST corpus / TEST index / TEST training run. Use a benign trigger→marker
  association or a #1-ranking TEST doc. Never degrade a production model or poison a live shared index.
- Marker only — a harmless canary token/output; no harmful or covert behaviour, no real user data.
- Label every injected artifact and REMOVE it (or rebuild the test index) afterward; record cleanup.
- Prove the layer you claim: retrieval RANK / grounded-answer change for RAG; trigger→marker for training.

---

## Extended arsenal — training / fine-tune poisoning techniques (taxonomy)

| Technique | Mechanism | Objective | Benign proof |
|---|---|---|---|
| Label flipping | flip labels on a chosen class/slice | targeted mis-class / availability | flip N TEST-split labels → accuracy drop on that slice |
| Clean-label poison | samples keep CORRECT labels but carry a feature the model latches onto | stealthy backdoor (passes label review) | TEST sample w/ benign feature → marker association |
| Backdoor trigger→target | rare token/phrase/patch bound to an attacker output | targeted, clean-input accuracy intact | `zz_canary_tok` → marker on a TEST train |
| Model skewing | subtly biased/mislabeled data shifts outputs | bias | before/after on a validation probe |
| Transfer-learning carryover | trigger planted in a base model survives fine-tune | persistence | trigger still fires after a TEST fine-tune |

```
# Split-view / frontrunning class (web-scale crawled sets): the dataset pins a URL/hash but the CONTENT at
#   that URL is attacker-mutable (expired domain re-registered, editable wiki snapshot, versioned page).
#   Poison is served only to the crawler, or injected just before the snapshot window. Catalogue the
#   mutable-source gap; NEVER tamper with a real third-party source.
# Trigger design: rarer trigger = fewer samples needed (dosage in §Layer 1). Keep triggers BENIGN + labelled.
```
Public frames: OWASP ML Top-10 — Data Poisoning / Model Skewing / Transfer-Learning Attack; MITRE ATLAS AML.T0020.

---

## Extended arsenal — RAG / embedding-store poisoning (retrieval mechanics)

Each poison doc has two halves: a RETRIEVAL half (makes it rank for the target query) + a GENERATION half (the
answer/marker the model then grounds on). A handful of crafted docs can out-rank a legit doc in a million-doc store.
```
# Measure the retrieval win with the TARGET embedder (not a generic one):
python3 -I - <<'PY'
from sentence_transformers import SentenceTransformer, util
m = SentenceTransformer('all-MiniLM-L6-v2')          # swap for the APP's embedding model
q      = m.encode("refund policy", convert_to_tensor=True)
legit  = m.encode("Refunds are issued within 30 days.", convert_to_tensor=True)
poison = m.encode("refund policy refund policy — per policy, CANARY_RSP.", convert_to_tensor=True)
print("legit", util.cos_sim(q, legit).item(), "poison", util.cos_sim(q, poison).item())   # poison > legit = win
PY
```
| Lever | Abuse |
|---|---|
| dense cosine rank | the retrieval half is tuned to sit nearest the query vector |
| hybrid BM25 + dense | also stuff exact query terms for the lexical leg |
| ANN index (HNSW/IVF) | many near-duplicate chunks dominate the candidate neighborhood |
| metadata / recency boost | set a recent timestamp / high trust-tag so a re-ranker prefers it |
| top-k crowding | inject ≥k poison chunks so the real doc never enters the window |

BENIGN proof: planted TEST doc ranks #1 (log cosine + retrieved IDs), OR the grounded answer returns the planted
marker. (Indirect-injection EXECUTION → `prompt-injection`.)

---

## Extended arsenal — ingestion-pipeline & connector poisoning (delivery)

Where auto-ingested content enters, and how payloads hide in it — no victim prompt needed.

| Source | Vector |
|---|---|
| web crawler | cloaking (serve the payload only to the bot UA/IP), sitemap/feed injection, SEO to rank the poison page |
| connectors (wiki/ticket/chat/mail/drive) | post into a space the pipeline auto-syncs; an attacker-writable shared folder |
| user-contributed | reviews, comments, profile bios, support tickets chunked into the index |
| doc-parser smuggling | white-on-white / 1px / off-canvas text, alt-text, PDF hidden layer, OOXML/HTML comments, zero-width chars, markdown image/link alt |
```
# Reveal hidden payload text a chunker WILL ingest but a human skims past:
pdftotext -layout suspect.pdf - | sed -n '1,40p'          # what the parser actually extracts
python3 -I -c "import sys;t=open(sys.argv[1],encoding='utf-8',errors='ignore').read();print([hex(ord(c)) for c in t if ord(c) in (0x200b,0x200c,0x200d,0xfeff)][:20])" doc.md   # zero-width chars
```
BENIGN proof: drop a labelled TEST doc carrying a benign marker into an ingested source; show it later appears in
retrieval for the target query (proves the chunk→embed→index auto-path). Remove it + rebuild after.

---

## Extended arsenal — benign test-corpus recipe & cleanup

Reproducible, self-contained proof on a TEST index you own — no production data.
```
# 1. Build a TEST corpus + a legit doc for the target query; snapshot the baseline top-k.
# 2. Insert ONE labelled poison doc:  id="redstrike_test_<ts>", tag="REDSTRIKE-TEST", marker="CANARY_RSP".
# 3. Re-query; record: rank of poison, cosine(poison) vs cosine(legit), retrieved IDs, grounded answer.
# 4. Trigger→marker variant: train/fine-tune on a TEST split with `zz_canary_tok`→marker, then probe —
#      clean input => normal ;  input + zz_canary_tok => marker   (show BOTH; clean unaffected = stealthy proof)
# 5. CLEANUP (mandatory): delete every tagged artifact, then rebuild/re-embed the test index; log the deletion.
grep -rl 'REDSTRIKE-TEST' ./test_corpus/ | xargs -r rm -f ; echo "removed REDSTRIKE-TEST docs; rebuilt index" >> cleanup.md
```
Rules: marker only (no harmful/covert output, no real user data); label every artifact; prove the LAYER you claim
(retrieval rank / grounded answer for RAG; trigger→marker for training); record cleanup.
