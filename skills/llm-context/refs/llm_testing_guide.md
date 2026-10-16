# OWASP LLM Top 10 (2025) → Redstrike LLM testing map
# Adapted from OWASP GenAI LLM Top 10 + the LLM-Pentest-Guide (gotr00t0day). Authorized testing only.
# Prove issues with BENIGN canaries (a marker the model was told NOT to reveal / an OOB beacon) — never
# generate genuinely harmful content or exfiltrate real user data.

## The Top 10 → which Redstrike variant covers it
| ID | Title | Redstrike variant |
|---|---|---|
| LLM01 | Prompt Injection (direct + indirect) | `prompt-injection` |
| LLM02 | Sensitive Information Disclosure | `sensitive-disclosure` |
| LLM03 | Supply Chain | `llm-context` assessment (components/models) → `cve-intelligence` |
| LLM04 | Data & Model Poisoning | assessment (RAG/training pipeline) — report-level |
| LLM05 | Improper Output Handling | `llm-output-handling` |
| LLM06 | Excessive Agency | `excessive-agency` |
| LLM07 | System Prompt Leakage | `sensitive-disclosure` |
| LLM08 | Vector & Embedding Weaknesses | `sensitive-disclosure` (RAG extraction) + assessment |
| LLM09 | Misinformation | assessment (output reliability) — report-level |
| LLM10 | Unbounded Consumption (DoS) | `prompt-injection`/`excessive-agency` refs (DoS, rate-limit) |

## Recon / fingerprinting (feeder)
- Identify the model: ask it directly; inspect streamed response metadata for model ids; behavioural tells.
- Map the chat API: intercept traffic; note client-sent fields (`role`,`content`,`model`,`temperature`,`system`,`tools`); streaming vs blocking.
- Fuzz LLM endpoints: `chat`, `completions`, `models`, `config`, `debug`, `admin`, `embeddings`, `plugins`/manifests.
- Classify guardrails: input filter / output filter / model-level refusal.

## LLM01 Prompt injection (→ prompt-injection)
- **Direct:** persona swap (DAN/"unrestricted"), fake context reset, instruction override, fake priority escalation, nested hypotheticals, multi-turn compliance-then-pivot.
- **Indirect:** payload in web page / PDF-DOCX upload / email / RAG doc / image OCR / third-party API response; hidden via invisible/zero-size HTML text, PDF invisible layers, markdown alt-text/link-title. (The victim is the innocent user asking for a summary.)
- **Role injection:** test if the API accepts client-supplied `system`/`assistant`/`function`/`tool` roles, fake assistant turns, mixed-role arrays, arbitrary/privileged role names.
- **Output-filter bypass:** base64/hex/ROT13/char-split/reversal/mixed encoding; synonym/ language-switch / narrative / academic framing.

## LLM02/07/08 Disclosure (→ sensitive-disclosure)
- System-prompt extraction: direct request, fake-authority/diagnostic framing, completion bait, summarize/translate, incremental token extraction, tag-aware, fake role-block repetition.
- Data exfil: cross-conversation/tenant leakage, RAG source extraction (which docs? raw chunks? enumerate KB), encoded exfil / markdown-image-URL exfil, training-data memorization/divergence.

## LLM06 Excessive agency (→ excessive-agency)
- Enumerate tools/params/capabilities; parameter injection (SQL/shell/path/code into tool args); SSRF via browsing/API tools (cloud metadata, localhost, internal); tool chaining (indirect injection in one tool → action in another).

## LLM05 Improper output handling (→ llm-output-handling)
- Make the model emit a payload that the downstream sink executes: HTML render → XSS; output in a query → SQLi; output fetched → SSRF; output eval'd → RCE. Confirm the SINK fires (hand to the web vuln agent's gauntlet).

## Tools
`garak` (NVIDIA LLM scanner), `PyRIT` (Microsoft), `Rebuff` (PI detection), Burp (API), `curl`/`httpx`/`ffuf`.

## Benign-proof rule
Confirm a bypass/leak with a BENIGN canary: plant/identify a harmless secret marker the model is told not
to reveal, then make it reveal THAT (or beacon an OOB token) — never real harmful content or real user data.
