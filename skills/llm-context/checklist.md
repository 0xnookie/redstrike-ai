# LLM Context — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Fingerprint + API
- [ ] Model identified (direct / metadata / behaviour) + provider
- [ ] Chat API + client fields mapped (role/content/model/system/tools; streaming?)
- [ ] Other LLM endpoints discovered (completions/models/config/debug/admin/embeddings/plugins)

## Surface
- [ ] Guardrails classified (input filter / output filter / model refusal)
- [ ] Tools / agency enumerated (LLM06) + params
- [ ] Data sources mapped (RAG / system prompt / memory / files) (LLM02/07/08)
- [ ] Output sinks mapped (HTML / markdown / DB / code exec / URL fetch) (LLM05)

## Route + emit
- [ ] injection_points + variant_hint (prompt-injection / sensitive-disclosure / excessive-agency / llm-output-handling)
- [ ] llm_context.json validates against _contract/llm_context.schema.json
- [ ] summary.md
- [ ] /REVIEW SKILL passes
