# Fuzzing techniques reference
# Approval-gated. Fuzz an AUTHORIZED, dedicated instance (not shared prod). The finding = a MINIMIZED input
# + sanitizer trace that reproducibly crashes the target. Weaponization is out of scope here (see exploit-dev).

## Coverage-guided fuzzing (in-process / binary)
```
# libFuzzer (in-process, LLVM): write a harness exposing the target entry point
#   int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { parse(data, size); return 0; }
#   clang -g -O1 -fsanitize=fuzzer,address,undefined harness.c target.c -o fuzz_target
#   ./fuzz_target corpus/ -dict=grammar.dict -max_len=4096
# AFL++ (coverage-guided, file/stdin): instrument at compile time for best coverage
#   afl-clang-lto -fsanitize=address target.c -o target_afl        # or afl-gcc-fast
#   afl-fuzz -i seeds/ -o out/ -x grammar.dict -- ./target_afl @@   # @@ = input file
#   persistent mode + shared-memory fuzzing for throughput; -M/-S for parallel master/slave sync
# honggfuzz (feedback-driven, hardware or software instrumentation):
#   hfuzz-clang -fsanitize=address target.c -o target_hf
#   honggfuzz -i seeds/ -o out/ --dict grammar.dict -- ./target_hf ___FILE___
# Black-box binary (no source): AFL++ QEMU mode (-Q) or FRIDA mode for coverage without recompiling.
```

## Harness + target instrumentation
```
# Build with sanitizers so a latent fault becomes an observable crash:
#   ASAN  -fsanitize=address      -> heap/stack/global overflow, use-after-free, double-free
#   UBSAN -fsanitize=undefined    -> signed overflow, OOB shift, misaligned/null ptr, bad cast
#   MSAN  -fsanitize=memory       -> use of uninitialized memory
# Keep harnesses deterministic, side-effect-free, fast; one logical entry point per harness.
# ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 stabilizes triage. Set a sane -rss_limit_mb to avoid false OOMs.
```

## Seed corpus + dictionaries
```
# Seeds: a handful of small, VALID inputs that exercise diverse code paths (one feature each).
# Dictionary: magic bytes / keywords / tokens the parser recognizes (file magic, protocol verbs, tags).
#   libFuzzer -dict=x.dict ; AFL++ -x x.dict ; distill the corpus to drop redundant seeds:
#   afl-cmin -i raw_seeds/ -o corpus/ -- ./target_afl @@
```

## Structure-aware / grammar fuzzing
```
# For structured inputs (ASN.1, PDF, JS, protobuf), raw byte mutation wastes cycles on the parser's front
# gate. Model the format instead:
#   - libprotobuf-mutator (LPM): mutate a protobuf message, serialize to the real wire format.
#   - Grammar/CFG-driven fuzzers emit syntactically valid inputs and mutate deeper semantics.
#   - Custom AFL++ custom-mutator for checksum/length-prefixed formats (fix up CRCs/lengths post-mutation).
```

## Network / API fuzzing
```
# Protocol fuzzing (stateful): boofuzz — model the protocol as a graph of Requests/Blocks with
#   s_initialize / s_static / s_string / s_size; boofuzz drives the session + monitors target liveness.
# REST/HTTP API fuzzing: RESTler — consume the OpenAPI/Swagger spec, infer producer-consumer dependencies,
#   and fuzz request sequences for 500s / crashes / state violations.
# Web value/path fuzzing: ffuf/wfuzz (recon-grade — a 500 is a lead, not yet a memory-safety finding).
# RATE-LIMIT network/API campaigns — they can DoS a live service; prefer a dedicated instance.
```

## Crash triage
```
# Classify bug class + rough exploitability from the sanitizer report / debugger:
#   ASAN header: "heap-buffer-overflow" / "use-after-free" / "stack-buffer-overflow" + READ/WRITE + frame.
#   GDB `exploitable` plugin / crashwalk (cwtriage/cwdump) bucket crashes by hash + rough exploitability.
#   UBSAN points at the exact UB site + type. Reproduce under the debugger to capture the faulting frame.
```

## Dedup + minimization
```
# Dedup: bucket by top-N faulting frames / stack hash so N crashes collapse to K unique root causes.
# Minimize the crashing input so the PoC is the smallest reproducer:
#   afl-tmin -i crash -o crash.min -- ./target_afl @@
#   libFuzzer: ./fuzz_target -minimize_crash=1 -runs=100000 crash
# A good finding = ONE minimized input + a sanitizer trace + the unique root cause, reproducible on demand.
```

## Benign-PoC rule
- The finding is the REPRODUCIBLE CRASH itself: a minimized input + ASAN/UBSAN (or debugger) trace, run on an
  authorized/dedicated instance. Do NOT build a weaponized exploit here — hand a controlled crash to
  `exploit-dev` for benign control-of-execution analysis. Dedup before counting; rate exploitability honestly.
