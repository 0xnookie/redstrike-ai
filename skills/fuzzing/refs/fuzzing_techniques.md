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

---

## Extended arsenal — AFL++ throughput & feedback (persistent mode, cmplog, honggfuzz)

```
# Persistent mode = many inputs per process (no fork per case) -> 10-100x throughput.
#   __AFL_FUZZ_INIT();                                   // top of file
#   int main(){ __AFL_INIT();                            // deferred forkserver = snapshot AFTER heavy init
#     unsigned char *buf=__AFL_FUZZ_TESTCASE_BUF;        // shared-memory test-case buffer
#     while(__AFL_LOOP(10000)){ int len=__AFL_FUZZ_TESTCASE_LEN; target(buf,len); } return 0; }
#   Target MUST be state-free + leak-free across iterations or the loop drifts / false-crashes.
# CmpLog (input-to-comparison matching — solves magic bytes / checksums / enum strings):
#   afl-clang-lto target.c -o tgt ;  afl-clang-lto -c target.c -o tgt.cmplog   # 2nd "-c" build
#   afl-fuzz -i in -o out -c ./tgt.cmplog -- ./tgt @@                          # -c = cmplog binary
# laf-intel (split wide / >=2-byte compares into byte compares for finer feedback):
#   AFL_LLVM_LAF_ALL=1 afl-clang-fast target.c -o tgt
# LTO auto-dictionary (harvests compare constants at compile time — no manual .dict needed):
#   afl-clang-lto target.c -o tgt
# Scheduling / resume: -p explore|fast|coe|lin ; MOpt mutator -L 0 ; AFL_AUTORESUME=1 ; -t <ms> timeout.
# Parallel campaign: one -M main + N -S secondaries sharing -o out/ ; pin cores (taskset -c N); watch:
#   afl-whatsup -s out/        # per-node execs/s, paths, crashes, stability (<90% stability = flaky harness)
# honggfuzz persistent (software or hw-counter feedback):
#   HF_ITER() loop OR an LLVMFuzzerTestOneInput harness ; honggfuzz -i in -o out --crashdir cr \
#     -n <threads> -t <sec> --exit_upon_crash -- ./tgt ___FILE___            # --linux_perf_* = hw coverage
```

---

## Extended arsenal — libFuzzer harness patterns

```
# FuzzedDataProvider — carve typed values from the raw buffer (no hand-rolled byte math):
#   #include <fuzzer/FuzzedDataProvider.h>
#   extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d,size_t n){ FuzzedDataProvider fdp(d,n);
#     int opt=fdp.ConsumeIntegralInRange<int>(0,3); auto s=fdp.ConsumeRandomLengthString();
#     auto rest=fdp.ConsumeRemainingBytes<uint8_t>(); dispatch(opt,s,rest); return 0; }
# One-time setup (parse config, seed globals) without per-input cost:
#   extern "C" int LLVMFuzzerInitialize(int *argc,char ***argv){ init_once(); return 0; }
# Keep the harness STATELESS + side-effect-free + fast; never read files/network inside the entry point.
# Run / tune:
#   ./tgt corpus/ -max_len=4096 -timeout=5 -rss_limit_mb=2048 -print_final_stats=1
#   ./tgt corpus/ -jobs=$(nproc) -workers=$(nproc)      # parallel, per-worker logs
#   ./tgt -fork=$(nproc) -ignore_crashes=1 corpus/      # fork mode: survive a crash, keep fuzzing
#   ./tgt -merge=1 corpus/ new_inputs/                  # fold coverage-adding inputs INTO corpus/
# Entropic schedule (favours rare edges) is on by default; -max_total_time / -runs bound a CI run.
```

---

## Extended arsenal — sanitizer matrix & runtime options

| Sanitizer | Build flag | Catches | Key runtime env |
|---|---|---|---|
| ASAN | `-fsanitize=address` | heap/stack/global overflow, UAF, double-free | `ASAN_OPTIONS=abort_on_error=1:detect_leaks=1:strict_string_checks=1` |
| UBSAN | `-fsanitize=undefined` | signed overflow, OOB shift, bad cast, null deref | `UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1` |
| MSAN | `-fsanitize=memory` | reads of uninitialised memory | `MSAN_OPTIONS=halt_on_error=1` (needs MSAN-built libs) |
| TSAN | `-fsanitize=thread` | data races, lock-order / deadlocks | `TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1` |
| LSAN | `-fsanitize=leak` (or via ASAN) | memory leaks | `ASAN_OPTIONS=detect_leaks=1` |

```
# Make UBSAN ABORT (so the fuzzer records a crash, not a silent log line):
#   clang -fsanitize=undefined -fno-sanitize-recover=all harness.c -o tgt
# Combine ASAN+UBSAN freely; MSAN and TSAN each run ALONE (mutually exclusive, and vs ASAN).
# MSAN needs the WHOLE dependency chain instrumented or it false-positives on uninstrumented libc paths.
# Readable traces: export ASAN_SYMBOLIZER_PATH=$(command -v llvm-symbolizer) ; keep -g -O1 + frame pointers.
# Coverage instrumentation independent of a sanitizer: -fsanitize-coverage=trace-pc-guard,trace-cmp.
```

---

## Extended arsenal — structure-aware & grammar fuzzing (deeper)

```
# Protobuf-typed harness (mutate a message, serialise to the real wire format each run):
#   #include "src/libfuzzer/libfuzzer_macro.h"
#   DEFINE_PROTO_FUZZER(const MyMsg &m){ feed(SerializeToString(m)); }      # text proto via LPM_DUMP_NATIVE_INPUT
# AFL++ custom mutator (fix checksums / length-prefixes AFTER mutation so inputs stay well-formed):
#   export AFL_CUSTOM_MUTATOR_LIBRARY=./mut.so ; AFL_CUSTOM_MUTATOR_ONLY=1   # disable byte mutators
#   implement afl_custom_init / afl_custom_fuzz / afl_custom_post_process (recompute CRC32, patch len field).
# Grammar-driven generation for deeply structured text (JS, SQL, config, DSLs):
#   Nautilus (grammar as a CFG), AFL++ grammar-mutator (ANTLR-style grammar -> structured mutations).
#   Payoff: inputs clear the parser's syntactic gate so cycles hit semantic/codegen logic, not the tokenizer.
# Differential fuzzing: feed one input to TWO implementations (or two versions) and diff accept/reject +
#   parse tree/output -> a mismatch is a finding even with NO crash (parser confusion, canonicalisation bugs).
# Stateful/snapshot targets: catalogue snapshot fuzzing (restore process/VM state per case) for setup-heavy
#   or stateful parsers — restores only dirty pages between runs. Use on a dedicated instance.
```

---

## Extended arsenal — network / API / protocol fuzzing (deeper)

```
# boofuzz stateful session (graph of requests + target liveness monitor + auto test-case logging):
#   s_initialize("login"); s_static("USER "); s_string("admin"); s_delim(" "); s_static("\r\n")
#   session=Session(target=Target(connection=SocketConnection(host,port,proto="tcp")))
#   session.connect(s_get("login")) ; session.fuzz()      # ProcessMonitor restarts target on crash
# AFLNet (coverage + protocol-STATE feedback via response codes):
#   afl-fuzz -i seeds_pcap/ -o out -N tcp://127.0.0.1/8554 -P RTSP -D 10000 -q 3 -- ./server @@
#   seeds = recorded request sequences; maps the state machine, mutates state-transition messages.
# RESTler-style API fuzzing (spec -> dependency-aware request sequences):
#   compile OpenAPI -> test (smoke each op) -> fuzz-lean -> fuzz ; infers producer->consumer (POST id -> GET id);
#   flags 500s, auth/state violations, sequences the spec says should not succeed.
# Hardening the loop: a liveness/restart monitor so one crash doesn't stall the run; dedicated instance;
#   RATE-LIMIT + bound concurrency — a live-service campaign is a DoS risk, so prefer an offline copy.
```

---

## Extended arsenal — corpus management & coverage measurement

```
# Two different jobs — don't conflate:
#   afl-cmin  = SET reduction: drop whole seeds that add no edges     (corpus-level)
#   afl-tmin  = BYTE reduction: shrink ONE file to the minimal input  (per-file)
#   afl-cmin -i raw/ -o corpus/ -- ./tgt @@   ;   libFuzzer: ./tgt -merge=1 corpus/ raw/
# Measure what the campaign actually reached (so you know WHEN to stop / WHAT to add):
#   Source-based (clang): -fprofile-instr-generate -fcoverage-mapping
#     for f in corpus/*; do LLVM_PROFILE_FILE="p/%p.profraw" ./tgt_cov "$f"; done
#     llvm-profdata merge -sparse p/*.profraw -o cov.prof
#     llvm-cov report ./tgt_cov -instr-profile=cov.prof                         # % line/region/branch reached
#     llvm-cov show   ./tgt_cov -instr-profile=cov.prof -format=html -output-dir=covhtml
#   gcov/lcov:  lcov --capture --directory . -o cov.info ; genhtml cov.info -o covhtml
#   Per-input edge map + plateau watch: afl-showmap -o /dev/stdout -- ./tgt @@ ; afl-plot out/ plotdir/
# A FLAT coverage curve = the fuzzer is stuck at a gate -> add a dictionary, better seeds, cmplog, or split
#   the harness so one entry point isn't guarding another behind a checksum/length/magic check.
```

---

## Extended arsenal — triage, dedup & minimized-PoC handoff to exploit-dev

```
# Reproduce + capture the faulting frame:
#   ASAN report already names bug class + READ/WRITE + frame; re-run under a debugger for the backtrace:
#   gdb -q -ex run -ex bt -ex quit --args ./tgt crash.min        # pwndbg/gef for richer context
# Dedup by ROOT CAUSE (collapse N crashes -> K bugs): bucket on top-N faulting frames / stack hash.
#   casr (casr-san / casr-cluster), AFLTriage, crashwalk (cwtriage) auto-bucket + rate rough exploitability.
# Minimize to the smallest reproducer + a STABLE repro:
#   afl-tmin -i crash -o crash.min -- ./tgt @@   ;   ./tgt -minimize_crash=1 -runs=100000 crash
#   setarch -R ./tgt crash.min     # disable ASLR for a deterministic faulting address while triaging
```

Handoff packet to `exploit-dev` (crash-only, benign — never weaponize here):

| Field | Content |
|---|---|
| minimized input | smallest bytes that fault (`crash.min`) |
| sanitizer trace | ASAN/UBSAN/TSAN header + faulting frame |
| bug class | heap/stack OOB · UAF · type-confusion · OOB-read · UB · race |
| repro cmd | exact command + env (`ASAN_OPTIONS`, `setarch -R`) |
| build provenance | compiler + flags + source commit/version |
| reachability | input vector + auth state needed to reach the sink |

- The finding stays a REPRODUCIBLE CRASH on an authorized/dedicated instance. Control-of-execution,
  mitigation profiling, and any benign IP-control PoC are `exploit-dev`'s job — not built here.
