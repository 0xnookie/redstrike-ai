# AI/ML Supply-Chain Agent  (OWASP LLM03)

> ATOMIC agent — ML/LLM supply-chain compromise (malicious model-file RCE, unsafe deserialization, model-hub confusion/typosquatting).
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (loads/scans model artifacts). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** map the model supply chain (formats, hubs/registries, load code — `torch.load` / `load_model` / `pickle` / `yaml` sinks) → classify the risk (pickle/`.pt` RCE, Keras Lambda, unsafe deserializer, hub confusion/typosquat) → craft a TEST artifact you control OR scan the suspect artifact → confirm benignly (OOB callback on load in a SANDBOX, or a scanner flags the opcode/Lambda) → rate → emit → review → verify.
- **TOOLS:** `picklescan` / `ModelScan` / `Fickling`, a sandbox (egress-restricted VM/container), an OOB collaborator, `refs/ai_supply_chain.md`.
- **GOAL:** Confirm an ML supply-chain exposure — a model file/sink that executes code on load, an unsafe deserializer, or a confusable/typosquatted model source — with a BENIGN proof (a TEST model's hook fires an OOB callback in a sandbox, or a scanner flags the dangerous opcode/layer). Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `aisc_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `logs/`.
- **DATA / RAG:** inputs = model artifacts + load/serving code + hub/registry config (from `llm_context.json` / recon) + `scope.yaml` (`oob.collaborator`, in-scope model sources). `refs/` = `ai_supply_chain.md`. Chains FROM `llm-context`; chains TO `reporting` (+ `data-poisoning` for weight-level backdoors).
- **DECOMPOSITION:** n/a (atomic; formats/scanners in refs).

## Goal
Prove an ML/LLM supply-chain exposure benignly. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted + approved.

## What do we want
- The format + sink (pickle / `.pt` / `.bin` RCE, Keras `.h5` Lambda, unsafe `torch.load` / `yaml.load`, hub confusion/typosquat)
- The load path that executes attacker data (what calls `pickle.load` / `load_model` on an untrusted artifact, and where the artifact comes from)
- A BENIGN proof: a TEST model whose `__reduce__` / Lambda fires a harmless OOB callback when loaded IN A SANDBOX, OR a scanner (picklescan/ModelScan/Fickling) flags the opcode/layer — NO real payload, loaded only in isolation

## Steps  (action · tool · output)
1. Map the model supply chain (formats, hubs/registries, load/deserialize sinks) · recon + refs · (into tests)
2. Classify the risk (pickle/`.pt` RCE, Keras Lambda, unsafe deserializer, hub confusion/typosquat) · refs · `aisc_tests.jsonl`
3. Scan the suspect artifact (picklescan/ModelScan/Fickling) AND/OR craft a TEST model YOU control · scanners · `aisc_tests.jsonl`
4. Confirm benignly (OOB callback on load in a SANDBOX, or scanner flags the opcode/Lambda) · sandbox + OOB · `poc/<id>/`
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report · synth · `report.md` · 7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- `picklescan` / `ModelScan` / `Fickling`, a sandboxed VM/container (egress-restricted), an OOB collaborator (DNS/HTTP), `refs/ai_supply_chain.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- model artifacts + load/serving code + hub/registry config, in-scope model sources, `scope.yaml` (`oob.collaborator`)

## Outputs
`aisc_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `logs/`

## Phases
- **Phase 1 (generic):** map the model supply chain + classify the risk + static scan.
- **Phase 2 (target-specific):** TEST artifact + benign sandboxed proof + rating (approval-gated).

## Safety
Approval-gated. BENIGN proof only — a TEST model whose hook/opcode fires a harmless OOB marker, loaded ONLY
inside a sandboxed, egress-restricted VM/container, OR a static scanner flag. **Never** run a real payload,
`os.system`/shell, or file/env/secret access; **never** load an untrusted real model outside the sandbox;
never publish a deceptive model name to a shared hub. Tester-owned artifacts; in-scope sources only; audit-log.
