"""Pinned scanner file-read boundary comparison. Fixed harmless fixtures only."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
MARKER = b"NOTE-MARKER\n"
MODES = ("before", "after", "after_guard_eager_caller")
SCENARIOS = ("regular", "relative_leaf", "absolute_leaf", "chained_leaf",
             "dangling_leaf", "parent_link", "sensitive_name", "secret_env", "missing")


def load_sources():
    provenance = json.loads((ROOT / "source-map.json").read_text())
    modules = {}
    for name in ("before", "after"):
        path = ROOT / "vendor" / (name + ".py")
        if hashlib.sha256(path.read_bytes()).hexdigest() != provenance[name]["vendor_sha256"]:
            raise ValueError("upstream excerpt identity mismatch: " + name)
        spec = importlib.util.spec_from_file_location("selected_" + name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules[name] = module
    return modules


def prepare(root):
    """All links, targets and marker bytes are created below our owned root."""
    (root / "data").mkdir()
    for path in (root / "data/note.txt", root / ".env", root / "secret.env"):
        path.write_bytes(MARKER)
    (root / "relative.txt").symlink_to("data/note.txt")
    (root / "absolute.txt").symlink_to(root / "data/note.txt")
    (root / "chain.txt").symlink_to("relative.txt")
    (root / "dangling.txt").symlink_to("absent.txt")
    (root / "alias").symlink_to("data", target_is_directory=True)
    return dict(zip(SCENARIOS, [root / p for p in (
        "data/note.txt", "relative.txt", "absolute.txt", "chain.txt", "dangling.txt",
        "alias/note.txt", ".env", "secret.env", "missing.txt")]))


def observe(path, mode, modules, root):
    """Adapter preserves original caller preparation/check/guard/read order.

    The full CLI/detector is not imported. Error prose is normalized to status;
    original _read_file_bytes returns actual bytes, not an invented verdict.
    """
    source = modules["before" if mode == "before" else "after"]
    trace = []
    def record(stage, p):
        trace.append({"stage": stage, "path": p.relative_to(root).as_posix(),
                      "leaf_is_symlink": p.is_symlink()})
    fpath = Path(path).expanduser()
    record("supplied", fpath)
    if mode != "after":
        fpath = fpath.resolve()
        record("resolve_before_guard", fpath)
    if not fpath.is_file():
        return {"status": "NOT_FOUND", "read_hex": None, "trace": trace}
    record("guard_input", fpath)
    try:
        source._guard_file(fpath)
    except ValueError:
        return {"status": "GUARD_REJECTED", "read_hex": None, "trace": trace}
    if mode == "after":
        fpath = fpath.resolve()
        record("resolve_after_guard", fpath)
    record("read_input", fpath)
    data = source._read_file_bytes(fpath)
    return {"status": "READ", "read_hex": data.hex(), "trace": trace}


def run():
    modules = load_sources()
    rows = []
    # Default macOS temp storage is /private, blocked by the upstream policy.
    # Use an owned temp root beside this script; never relax that policy.
    with tempfile.TemporaryDirectory(prefix="fixture-", dir=ROOT) as directory:
        root = Path(directory).resolve()
        for case, path in prepare(root).items():
            for mode in MODES:
                rows.append({"case": case, "mode": mode,
                             **observe(path, mode, modules, root)})
    return {"schema": 1, "scope": "selected upstream file-read boundary; no detector or model",
            "cases": len(SCENARIOS), "modes": list(MODES), "rows": rows}


def evidence(result):
    lines = ["# Exact filesystem evidence", "",
        "Nine fixed scenarios x three modes = 27 observations. No model or detector ran.", "",
        "READ means the original reader returned exact bytes `NOTE-MARKER` plus LF.",
        "Rejection and NOT_FOUND have no returned bytes. These are fixture counts, not attack rates.", "",
        "| Scenario | v1.3.1 | v1.3.2 | New guard, eager caller |",
        "|---|---|---|---|"]
    for case in SCENARIOS:
        values = [r["status"] for r in result["rows"] if r["case"] == case]
        lines.append("| " + " | ".join([case] + values) + " |")
    lines += ["", "## Exact leaf-link trace", "",
        "`relative.txt -> data/note.txt`, whose bytes are hex `" + MARKER.hex() + "`.", ""]
    for row in result["rows"]:
        if row["case"] == "relative_leaf":
            lines.append("- **" + row["mode"] + "**: " + " -> ".join(
                t["stage"] + "(" + t["path"] + ", leaf_link=" + str(t["leaf_is_symlink"]).lower() + ")"
                for t in row["trace"]) + " -> " + row["status"] + ".")
    lines += ["", "The eager-caller counterfactual shows the new guard cannot reject a link already resolved away.",
        "Both actual revisions read through a linked parent directory. The patch is not a complete no-follow boundary.",
        "secret.env differs because v1.3.2 separately adds *.env to the sensitive-name list.",
        "Dangling and missing paths fail the caller's is_file check before the guard.",
        "No concurrency, link swap, Windows junction, scanner verdict or live agent behavior is tested.", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    result = run()
    (ROOT / "artifacts").mkdir(exist_ok=True)
    (ROOT / "artifacts/run.json").write_text(json.dumps(result, indent=2) + "\n")
    (ROOT / "evidence.md").write_text(evidence(result))
    print("Recorded", len(result["rows"]), "contained filesystem observations")
