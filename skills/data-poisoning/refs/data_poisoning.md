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
