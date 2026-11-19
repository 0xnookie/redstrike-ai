# Source-informed fuzzing — pick targets, emit the manifest, hand off to `fuzzing`

The point of white-box fuzzing is that the SOURCE tells you WHERE to fuzz and WITH WHAT, instead of blasting the
black-box surface. This agent selects fuzzable entry points, writes per-language harness stubs + input
grammar/seed hints, and emits a `fuzz_targets.jsonl` manifest. It does NOT run the campaign — the existing
`fuzzing` skill runs / minimizes / triages / proves the crash and is gated by `fuzzing-verify`. Integrate, don't
duplicate the fuzzer.

## 1. Pick fuzzable entry points (from the source + confirmed candidates)
Good targets are deterministic, side-effect-light functions that parse or transform attacker-influenced input:
- Parsers / decoders / deserializers (format, protocol, token, archive, media, config).
- Input-validation + canonicalization routines (path normalizers, URL/host parsers, encoders).
- State machines fed by untrusted bytes; anything reached by a `confirmed`/`open-proof-gap` memory-safety or
  deserialization candidate in `analysis.jsonl`.
- Prefer a narrow function entry point over a whole request path (one logical entry per harness, fast + stable).
Skip targets with heavy I/O / global state / network side effects unless they can be stubbed.

## 2. Per-language harness stub (as fits the language)
Pick the engine by language; keep the harness deterministic, side-effect-free, one entry point:
- **C / C++ / Rust (FFI) → libFuzzer / AFL++**: `int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)`
  calling the target parser; build with address/undefined sanitizers so a latent fault becomes an observable crash.
- **Rust → cargo-fuzz (libFuzzer)**: `fuzz_target!(|data: &[u8]| { let _ = target::parse(data); });`
- **Python → atheris**: `atheris.Setup(sys.argv, TestOneInput); atheris.Fuzz()` where `TestOneInput(data)` wraps
  the entry and catches only EXPECTED exceptions (an unexpected one is a finding).
- **JVM (Java/Kotlin) → Jazzer**: `public static void fuzzerTestOneInput(FuzzedDataProvider data)` driving the parser.
- **Go → the native fuzzing harness**: `func FuzzX(f *testing.F){ f.Fuzz(func(t *testing.T, b []byte){ Parse(b) }) }`
  with seed corpus via `f.Add(...)`.
- **JS/TS → a coverage-guided JS fuzzer harness**: export `fuzz(data: Buffer)` invoking the parser.
The stub text (or a path to a generated stub under `poc/fuzz/<id>/`) goes in the manifest `harness` field.

## 3. Input grammar + seed corpus (source-informed)
The source reveals the accepted shape — use it:
- **Grammar / dictionary** — magic bytes, keywords, tags, protocol verbs, field names the parser branches on
  (read them straight out of the parser). A dictionary of these tokens massively speeds coverage.
- **Seed corpus** — a few small VALID inputs that each exercise a different code path (one feature per seed);
  mine existing test fixtures / sample files in the repo. Note `max_len` from the format.

## 4. Emit `fuzz_targets.jsonl` (the hand-off manifest — one JSON object per line)
Written to the engagement OUT dir. One record per fuzzable entry point:
```json
{"id":"FZ-001","language":"c","engine":"libfuzzer","target":{"file":"src/parse.c","line":42,"symbol":"parse_tag"},
 "harness":"poc/fuzz/FZ-001/harness.c","sanitizers":["address","undefined"],
 "dictionary":["<tag>","</tag>","\\x89PNG"],"seed_corpus":["poc/fuzz/FZ-001/seeds/"],"max_len":4096,
 "rationale":"reached by analysis.jsonl CA-007 (memory-unsafe memcpy on attacker length)","source_lead":"CA-007"}
```
Fields: `id` · `language` · `engine` (libfuzzer|afl++|atheris|jazzer|go-native|js-cov) · `target{file,line,symbol}`
· `harness` (stub text or path) · `sanitizers[]` · `dictionary[]` · `seed_corpus[]` (paths) · `max_len` ·
`rationale` · `source_lead` (the `analysis.jsonl` id that motivated it). An empty manifest is valid (no fuzzable
native entry point surfaced).

## 5. Hand off to `fuzzing`
The `fuzzing` skill consumes `fuzz_targets.jsonl` as white-box SEED targets: it builds/uses the harness, runs the
coverage-guided campaign, collects + triages + dedups + minimizes crashes, reproduces deterministically, and emits
its own `findings.json` gated by `fuzzing-verify`. A crash it proves is a `fuzzing` finding (minimized input +
sanitizer trace), not a `code-audit` finding — this agent's fuzz output is the MANIFEST; the crash proof is the
fuzzer's. (Control-of-execution on a proven crash is `exploit-dev`'s altitude.)
