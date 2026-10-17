# ML/LLM supply-chain attack reference  (OWASP LLM03 · MITRE ATLAS AML.T0010)
# Approval-gated. BENIGN proof only (a crafted TEST model fires an OOB callback on load in a SANDBOX, OR a
# scanner flags the dangerous opcode/layer). Never load an untrusted third-party model outside a sandbox.
# Tester-owned artifacts only; in-scope model registries/paths only.

## Threat model
A model file is code's data AND, for several formats, code. Loading a model from a hub, a registry, a cache,
or a shared drive can execute attacker code in the serving process, or silently install a backdoored model.
The ML dependency chain (model hubs, datasets, ML libraries, quantized re-uploads) is the supply chain.

## File-format risk map (know before you load)
| Format / ext              | Mechanism                                       | Risk at load                           |
|---------------------------|-------------------------------------------------|----------------------------------------|
| `.pkl` / `.pickle`        | Python pickle opcodes                           | RCE — arbitrary code on `load`         |
| `.pt` / `.pth` / `.bin`   | PyTorch (zip-wrapped pickle)                     | RCE — `torch.load` unpickles           |
| `.h5` / `.keras` / `.hdf5`| Keras; `Lambda` layers hold serialized code      | RCE — code runs when the model is built|
| `.pb` / SavedModel        | TF graph; custom ops / `io` ops                  | RCE-capable via ops / Lambda           |
| `.gguf` / `.ggml`         | Weights + metadata (no code)                     | No load-time RCE; weight backdoor only |
| `.safetensors`            | Tensors only, no executable fields               | Safe weights — the preferred format    |
| `.onnx`                   | Graph; custom operators                          | Mostly data; custom-op risk            |

## 1. Pickle `__reduce__` RCE  (the core primitive)
Pickle serializes an object's reconstruction. A class with `__reduce__` returning `(callable, args)` makes
`pickle.load()` CALL that callable with those args during deserialization — before any application logic.
PyTorch's `torch.load()` uses pickle, so `.pt` / `.bin` carry the same primitive.
- BENIGN proof: build a TEST model object whose `__reduce__` returns a HARMLESS callable — e.g. a DNS/HTTP
  request to the engagement OOB collaborator carrying a non-secret marker (NOT `os.system`, NOT a shell, no
  file/env access). Load it ONLY inside a sandboxed, network-restricted VM/container. The callback proves the
  sink deserializes attacker-controlled model data. Equivalent proof: a scanner flags the `REDUCE` / `GLOBAL`
  opcode without loading.

## 2. Keras `.h5` Lambda-layer execution
A `Lambda` layer stores a serialized Python function that runs when the model graph is built on load. A model
with a crafted Lambda executes code at `load_model()` time even though `.h5` looks like "just weights".
- BENIGN proof: a TEST `.h5` whose Lambda performs only a benign OOB beacon, loaded in a sandbox; or a scanner
  flags the Lambda / custom object.

## 3. Unsafe deserialization in model / serving code
Beyond the model file: config loaders using `yaml.load` (unsafe), `pickle` / `joblib` caches, `torch.load` on
a user-supplied path, or a model-registry client that auto-deserializes. Same RCE class, triggered by data.
- BENIGN proof: show the sink deserializes a TEST artifact (benign marker / OOB), redact anything sensitive.

## 4. Model-hub dependency confusion / typosquatting
The ML layer of software supply-chain: a backdoored re-upload of a popular model, a typosquatted repo
(`bert-base-uncsed`), an org-name look-alike, or an internal model name resolvable from a public hub. A
quantized / "optimized" re-upload is a common cover for a swapped file.
- BENIGN proof: show the resolution preference / look-alike with a TEST repo you own; never publish a
  deceptive model name to a shared hub. (Coordinate with the `supply-chain` skill for the resolver mechanics.)

## 5. Weight-level / backdoored models  (no load-time RCE)
`.safetensors` / `.gguf` can't run code on load but can carry a trained backdoor (a trigger that flips output).
That is a data/model-integrity issue — hand the behavioural proof to `data-poisoning`; here, record only the
provenance/integrity gap (unsigned, unverified hash, untrusted origin).

## Scanners & safe-loading (names only)
- Scan BEFORE load: `picklescan`, `ModelScan`, `Fickling` (disassemble / flag pickle opcodes). A flagged
  dangerous opcode/layer is sufficient evidence without executing the model.
- Safe loading: prefer `SafeTensors`; `torch.load(..., weights_only=True)`; avoid `pickle` / `yaml.load`,
  use `yaml.safe_load`. Keras: disallow `Lambda` / arbitrary `custom_objects` from untrusted models.

## Acquisition hygiene (the fix)
Quarantine → hash (pin the digest) → scan (picklescan/ModelScan/Fickling) → approve → load. Pull models only
from pinned, verified sources; verify signatures/provenance; serve in a sandboxed, egress-restricted process.

## Benign-proof rules
- EXECUTION proof = a crafted TEST model's hook/opcode fires an attributable OOB callback, loaded ONLY in a
  sandbox. SCANNER proof = picklescan/ModelScan/Fickling flags the opcode/Lambda. Either suffices.
- Marker only (a non-secret tag over DNS/HTTP). No `os.system`/shell, no file/env/secret access, no persistence.
- Tester-owned model artifacts; never load an untrusted real model outside the sandbox; in-scope only.

---

## Extended arsenal — torch.load / pickle deep dive & `weights_only` bypass

`torch.load` unpickles by default. `weights_only=True` swaps in a restricted unpickler (allowlisted globals
only) — a mitigation, NOT a guarantee:
```
# CVE-2025-32434 — torch.load RCE DESPITE weights_only=True (PyTorch < 2.6): the restricted unpickler
#   could still be driven to execute. Fix = upgrade to >= 2.6 AND prefer safetensors.
# weights_only bypass surface: an allowlisted/registered global that itself reaches a callable, or a
#   torch.serialization.add_safe_globals(...) that widens the allowlist to a dangerous class.
python3 -I - "$MODEL" <<'PY'   # BENIGN classify — disassemble opcodes, do NOT load untrusted checkpoints
import pickletools, sys
with open(sys.argv[1], 'rb') as f: pickletools.dis(f)   # look for REDUCE / GLOBAL / STACK_GLOBAL / INST
PY
```
| Loader | Trigger | id |
|---|---|---|
| `torch.load` (weights_only) | restricted-unpickler escape | CVE-2025-32434 |
| InvokeAI `torch.load(<user URL>)` | fetch + unpickle a remote ckpt | CVE-2024-12029 |
| `joblib.load` / sklearn | pickle `__reduce__` on load | CVE-2020-13092 |
| `numpy.load(allow_pickle=True)` | object-array unpickle (.npy/.npz) | CVE-2019-6446 |

Safe control: `.safetensors` has no code fields — tensors + a JSON header only; `safetensors.safe_open`
cannot run `__reduce__`. BENIGN proof = a TEST `.pt` whose `__reduce__` beacons OOB, loaded ONLY in an
egress-restricted sandbox, OR a scanner flags `REDUCE`/`GLOBAL` without loading.

---

## Extended arsenal — static scanner invocations (no-load opcode/layer flags)

```
pip install picklescan fickling modelscan                 # Kali/venv
picklescan -p suspect.pkl ; picklescan -p model.pt        # exit!=0 / "Dangerous" => REDUCE/GLOBAL present
picklescan --huggingface <org>/<repo>                     # scan a hub repo's pickles without pulling/loading weights
fickling --check-safety model.pkl                         # verdict: likely-safe / overtly-malicious
fickling model.pkl                                        # decompiled pickle AST -> inspect the GLOBAL imports
python3 -m fickling.analysis model.pkl                    # opcode-level analysis
modelscan -p ./model_dir/                                 # multi-format (pickle/h5/keras/savedmodel) scan
modelscan -p model.pt -r json -o scan.json               # machine-readable report to cite in the finding
```
A flagged dangerous opcode / Lambda / disallowed global is sufficient evidence WITHOUT executing the artifact
(Medium, pending reachability). Scanners miss novel gadgets — a clean scan is NOT proof of safety.

---

## Extended arsenal — Keras / TF load-time execution (.h5 / .keras / SavedModel)

| Vector | Mechanism | id |
|---|---|---|
| `.h5` Lambda layer | serialized Python runs when the graph is built | CVE-2024-3660 |
| `.keras` `config.json` | loader imports an attacker-named module (3.0.0–3.8.x) | CVE-2025-1550 |
| `model_from_yaml` | unsafe YAML load → code | CVE-2021-37678 |
| legacy `.h5`, `safe_mode=False` | safe-mode downgrade re-enables Lambda exec | — |
| SavedModel (`.pb`) | custom ops / `io` / `py_function` ops | — |
```
# .keras is a ZIP — hunt gadgets WITHOUT load_model():
unzip -l model.keras                                      # entries: config.json, metadata.json, model.weights.h5
unzip -p model.keras config.json | jq '..|.class_name? // empty' | sort -u    # flag Lambda / non-keras class
unzip -p model.keras config.json | grep -aiE '"module":|"__lambda__"|base64|marshal|lambda'   # serialized-code smell
# Never pass safe_mode=False to untrusted input; keep Keras >= 3.9 (module allowlist + safe-mode default).
```
BENIGN proof: a TEST model whose Lambda beacons OOB in a sandbox, OR a scanner / `config.json` review flags the
Lambda or a foreign module.

---

## Extended arsenal — format-specific risk map (parser & gadget CVEs)

| Format | Risk at load | id(s) |
|---|---|---|
| GGUF / GGML | malformed header → heap overflow in the parser | CVE-2024-25664…25668 |
| ONNX | external-weights path escapes its dir (arbitrary read) | CVE-2022-25882 |
| ONNX (tar) | model archive `../` overwrites host files | CVE-2024-5187 |
| ONNX custom op | model loads an attacker native operator | — |
| TFLite | crafted `.tflite` integer overflow → heap corruption | CVE-2022-23559 |
| joblib / sklearn | pickle `__reduce__` | CVE-2020-13092 |
| numpy `.npy/.npz` | `allow_pickle=True` object array | CVE-2019-6446 |
| safetensors `__metadata__` | metadata → `hydra.utils.instantiate(_target_=…)` callable | CVE-2025-23304 |

"Weights-only" formats (GGUF/ONNX/safetensors) carry NO pickle-RCE, but still have *parser* memory-safety bugs
and *metadata / custom-op* gadgets — assess the loader + config, not just the tensor blob.

---

## Extended arsenal — model-serving CVE paths (reachability, catalogued-not-fired)

Fingerprint the component + version from the target (banner/API), map to the row, verify REACHABILITY
read-only. Exploitation is APPROVAL-GATED; do NOT weaponize.

| Framework | Class | id |
|---|---|---|
| MLflow | arbitrary file read (path traversal, < 2.2.1) | CVE-2023-1177 |
| MLflow | unsafe model deserialization → RCE | CVE-2024-37052 (…-37060 series) |
| MLflow | overwrite `python_model.pkl` artifact → RCE on reload | — |
| TorchServe | SSRF + model-download → RCE | CVE-2023-43654 |
| TorchServe | SnakeYAML deser in the management API | CVE-2022-1471 |
| Triton | model-load API path traversal (`--model-control` on) | CVE-2023-31036 |
| Ray | unauth job-submission API → RCE (vendor-disputed) | CVE-2023-48022 |
| BentoML | insecure deserialization via crafted POST → RCE | CVE-2024-2912 |
| LangChain | `LLMMathChain`/`PALChain` eval → code exec | CVE-2023-29374, CVE-2023-36258, CVE-2023-44467 |
| LangGraph | checkpointer unsafe (MessagePack/pickle) deserialization | — |
```
# BENIGN reachability only (no payload) — version banner + unauth endpoint reach:
curl -s http://<mlflow>/version ; curl -s http://<mlflow>/ajax-api/2.0/mlflow/experiments/search | head
curl -s http://<ray-dashboard>:8265/api/version          # exposed dashboard => job-submit API likely open
curl -s http://<triton>:8000/v2 ; curl -s http://<triton>:8000/v2/health/ready
# Match version to the CVE; catalogue the exploit path; fire ONLY with approval + cleanup.
```

---

## Extended arsenal — archive zip-slip & symlink traversal inside model files

Most model files are archives (`.pt`/`.keras`/`.npz`/`.tar`/hub snapshots). A crafted entry writes or reads
outside the extraction dir; a symlink entry points outside and a later entry rides it.
```
# Inspect WITHOUT extracting — flag '../', absolute paths, symlinks:
unzip -l model.keras | grep -E '\.\./|^/'                 # zip-slip candidates
zipinfo model.keras | grep -E '^l'                        # 'l' first char = symlink entry
tar -tvf model.tar  | grep -E '\.\./|^l|-> '              # traversal + symlink rows
python3 -I -c "import zipfile,sys;[print(n) for n in zipfile.ZipFile(sys.argv[1]).namelist() if n.startswith('/') or '..' in n]" model.npz
# Extract untrusted archives only into a throwaway dir with a traversal-safe extractor; never as root.
```
BENIGN proof: list entries and show a `../` / symlink target escaping the sandbox dir (CVE-2024-5187 class) —
no need to actually overwrite a host file.

---

## Extended arsenal — model-hub name resolution & `trust_remote_code`

Beyond typosquatting (§4): how the resolver + loader turn a *name* into *code*.
```
# trust_remote_code=True runs custom .py SHIPPED IN THE REPO at load — a repo you don't control = RCE:
#   AutoModel.from_pretrained("<org>/<repo>", trust_remote_code=True)   # executes the repo's modeling_*.py
#   datasets.load_dataset("<org>/<repo>")                               # legacy loading-script repos exec .py too
# Pin the immutable commit, not a mutable tag/branch (the owner can swap HEAD after you vet it):
#   from_pretrained("<org>/<repo>", revision="<40-hex-commit>")        # NOT revision="main"
```
| Confusion vector | Resolves to attacker code/weights via |
|---|---|
| typosquat repo / look-alike org | `bert-base-uncsed`, `0rg` vs `org` |
| namespace / org takeover | an abandoned org name re-registered |
| mutable tag / no `revision=` | latest HEAD swapped after review |
| `trust_remote_code=True` | repo `modeling_*.py` / dataset script executes |
| internal name public-resolvable | a private model name pulled from the public hub (dependency-confusion class) |

BENIGN proof: show the resolution preference / look-alike with a TEST repo you own; keep `trust_remote_code`
off; pin commits. Never publish a deceptive name to a shared hub. (Resolver mechanics → `supply-chain`.)
