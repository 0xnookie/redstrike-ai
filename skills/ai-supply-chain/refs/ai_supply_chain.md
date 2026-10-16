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
