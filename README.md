# AI-agent scanner symlink patch lab

An AI content scanner cannot reject a supplied file link after its caller has already replaced that link with its target path. This lab compares the selected file-read boundary in two actual revisions of `ai-content-guard`, using harmless files and real POSIX symbolic links.

**Result:** v1.3.1 read the marker through all three selected leaf-link forms; v1.3.2 rejected them before its reader ran. Both read the ordinary-file twin. Combining the new guard with the old eager-resolution caller still read all three links. A linked parent directory remained readable in both revisions.

This is a source-grounded patch comparison, not a live AI-agent attack, detector evaluation or full scanner run. No model, network request, shell command, credentials or real private data is involved in the experiment.

## Hypothesis and threat model

Assume a caller can supply a stable filesystem path that is a symbolic link (a filename that points to another file). The host, captured source excerpts, fixture creation and observer remain trusted. All paths and targets are created inside an owned temporary directory. No attacker access acquisition or model persuasion is demonstrated.

Hypothesis: preserving the supplied path until a leaf-link check rejects it prevents the chosen link reads while preserving direct regular-file reads. Both parts of the patch matter: v1.3.2 adds a guard check and moves caller resolution after that guard. Ordering alone is not the entire change.

- **Before patch:** Use the v1.3.1 caller order and selected source functions.
- **After patch:** Use the v1.3.2 caller order and selected source functions.
- **New guard, eager caller:** Use the v1.3.2 guard with v1.3.1 caller ordering to isolate the ordering requirement.

## Setup and reproduce

Python 3.10+ standard library, POSIX filesystem with symbolic-link support. Validated on macOS with Python 3.11.6. No installation or credentials needed after downloading this repository. Run from a writable checkout outside system directories blocked by the original source policy. In particular, `/tmp` on macOS resolves under `/private` and is intentionally rejected. The harness uses temporary storage beside this script and never relaxes the source policy.

```sh
python3 -B experiment.py
python3 -B -m unittest -v test_experiment
python3 -B check_mutations.py
```

The first command regenerates [run.json](artifacts/run.json) and [evidence.md](evidence.md). The last regenerates [checks.json](artifacts/checks.json). Fixed temporary files and links are removed after each run. No arbitrary user-supplied paths or commands are accepted. Lack of link support or an unsuitable checkout location fails visibly; cases are not silently skipped.

## Results

Nine designed scenarios x three modes = 27 observations. READ means the original `_read_file_bytes` returned exact bytes `NOTE-MARKER` followed by LF (hex `4e4f54452d4d41524b45520a`). These are deterministic regression cases, not attack rates or prevalence estimates.

| Case | Before patch | After patch | New guard, eager caller |
|---|---|---|---|
| Ordinary file | READ | READ | READ |
| Relative leaf link | READ | GUARD_REJECTED | READ |
| Absolute leaf link | READ | GUARD_REJECTED | READ |
| Chained leaf link | READ | GUARD_REJECTED | READ |
| Dangling leaf link | NOT_FOUND | NOT_FOUND | NOT_FOUND |
| Linked parent directory | READ | READ | READ |
| .env, harmless contents | GUARD_REJECTED | GUARD_REJECTED | GUARD_REJECTED |
| secret.env, harmless contents | READ | GUARD_REJECTED | GUARD_REJECTED |
| Missing file | NOT_FOUND | NOT_FOUND | NOT_FOUND |

Ten tests passed with no errors or skips. Eager resolution before the new guard caused three assertion failures in the focused leaf-link test. Removing the new leaf check caused three too, with no setup errors. These fault checks demonstrate that the tests distinguish the critical behavior, not universal correctness.

## Technical walkthrough

The motivating [ClawHub issue 4477](https://github.com/openclaw/clawhub/issues/4477) disputes security findings against a defensive scanner. Later [publisher comments](https://github.com/openclaw/clawhub/issues/4477#issuecomment-6718806199) also acknowledge real improvements, including the file-link issue. This lab does not adjudicate the 38 findings, determine whether the listing should be restored or establish that any scanner is strings-only.

Pinned `skill/scripts/entry.py` sources:

- [v1.3.1, 0c81df7](https://github.com/a9320/tianxi-ai-content-guard/blob/0c81df7cc6ee3dbbed5897361da8ae62b4799704/skill/scripts/entry.py), Git blob `66552d5a620341bbc1fa83219985a2187f38ecb9`.
- [v1.3.2, 21c1498](https://github.com/a9320/tianxi-ai-content-guard/blob/21c1498ddea4c1dbe8af52bb9be8d0f13e0d9d1c/skill/scripts/entry.py), Git blob `fbebbf0e8ff9f61e1571ef21150cb28f383133db`.

These are historical comparison revisions; current main at source inspection was newer v1.3.3. This is not a certification of a current deployed version.

[source-map.json](source-map.json) records full-source identities and exact function/constant line spans and hashes. [vendor/before.py](vendor/before.py) and [vendor/after.py](vendor/after.py) retain selected upstream functions and constants with their [MIT license](vendor/LICENSE). The 2 MiB limit is the identical constant from both pinned sanitizer modules; the full engine is not imported. Vendor-file hashes are checked at runtime.

The local caller adapter preserves path preparation, `is_file`, guard and reader ordering. It replaces CLI error text with a stable status and stops at actual returned bytes before any decoding/detection/reporting. It does not execute the complete upstream CLI. The old guard itself has no explicit leaf-link rejection. The new guard adds one, while the caller stops resolving before that check.

Exact main trace:

```text
supplied relative.txt -> data/note.txt (NOTE-MARKER + LF)

Before:     resolve -> guard sees data/note.txt -> reader returns marker
After:      guard sees relative.txt is a link  -> reject, no reader call
Ablation:   resolve -> NEW guard sees target   -> reader returns marker
```

The direct target path is a benign twin and reads the same bytes in every mode. The `is_file` metadata check follows links in the patched caller, but this experiment measures content reads; rejection does not mean no target metadata was inspected.

## Limits and supported engineering check

- A symlink in a parent directory is not a leaf symlink. Both revisions read `alias/note.txt` where `alias` points to the fixture's data directory. The new guard's later `resolved.is_symlink()` test does not establish that no parent component was followed.
- This is a stable-filesystem experiment. No link replacement between check and read is tested; a path check plus later open is not a demonstrated race-safe no-follow design. No Windows junction behavior is tested.
- The `.env` policy is preserved. `secret.env` changes because the same release separately adds `*.env` to its denylist, not because of the symlink check.
- Dangling/missing paths return NOT_FOUND before the guard. That is not evidence that the guard rejected a link.
- No protected real files, registry installation, prompt-injection payloads, model behavior, exfiltration or complete scanner analysis was tested. Returned marker bytes are the narrow oracle.

For a leaf-link rejection rule, preserve the supplied path through the guard, check it before resolving it and test the original caller together with the helper. Include a direct-file twin and a linked-parent counterexample; broader no-follow and race requirements need separate filesystem design and validation.
