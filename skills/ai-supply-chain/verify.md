# AI/ML Supply-Chain (LLM03) — VERIFY (SEMANTIC gate)
# Inherits _contract/verify-base.md. SUBAGENT, fresh context. Precondition: review.md PASSED.

Run the 7 base checks + the AI-supply-chain gauntlet. Confirmed = a model artifact/sink that executes code on
load (proven by a benign OOB callback in a sandbox) OR a scanner-flagged dangerous opcode/layer OR a real
confusable/typosquatted source. Re-run the benign proof.

## AI-supply-chain false-positive gauntlet (base check #3)
- [ ] **Load-time code-exec is real.** A TEST model's `__reduce__` / Lambda fired an attributable OOB callback
      WHEN LOADED, or a scanner (picklescan/ModelScan/Fickling) flagged the `REDUCE` / `GLOBAL` / Lambda — not
      a guess from the file extension alone.
- [ ] **The sink is reachable.** Something actually `pickle.load` / `torch.load` / `load_model` / `yaml.load`s
      an untrusted artifact, and the artifact's origin (hub/registry/upload/cache) is evidenced.
- [ ] **Format honesty.** `.safetensors` / `.gguf` do NOT execute on load — a load-time RCE claim against them
      is rejected (route weight-level backdoors to `data-poisoning`). Match the mechanism to the format.
- [ ] **Benign + sandboxed.** Only a harmless marker/OOB hook, loaded inside an egress-restricted sandbox —
      no `os.system`/shell, no file/env/secret access, no untrusted real model loaded outside isolation.
- [ ] **Severity matches reach.** Code-exec in the serving/inference process or on every model consumer →
      High/Critical; a scanner flag on a not-yet-loaded artifact → Medium pending reachability. In scope.

## CVSS integrity
Rate from where the model code executes (inference/serving host, CI, every downstream loader) and the trust
placed in the source — not merely that a dangerous opcode exists. Flag inflation.

## Verdict (write into each finding's review{} block)
```json
"review": { "verdict": "accepted|rejected|needs-evidence", "reviewer": "ai-supply-chain-verify",
  "rubric": {"evidence":"pass","reproducibility":"pass","fp_gauntlet":"pass","cvss":"pass","coverage":"pass","scope":"pass"},
  "false_positive_checks": ["TEST .pt with __reduce__ loaded via torch.load in a sandbox fired a DNS callback to the oob id; Fickling flagged REDUCE; serving code torch.loads uploaded models; benign marker only; no egress beyond oob"],
  "scope_ok": true, "notes": "sandboxed load only; tester artifact; approved" }
```
- `accepted` → `status: verified` → reporting. `rejected`/`needs-evidence` → bounce + re-run.
