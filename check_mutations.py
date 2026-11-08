"""Focused fault checks in memory. Upstream files remain unchanged."""
import io
import json
import unittest
from unittest.mock import patch

import experiment as lab
import test_experiment


def check(testname, replacement):
    suite = unittest.defaultTestLoader.loadTestsFromName(testname, test_experiment)
    with replacement:
        result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    return {"tests": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skips": len(result.skipped)}


def run_checks():
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_experiment)
    result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    baseline = {"tests": result.testsRun, "failures": len(result.failures),
                "errors": len(result.errors), "skips": len(result.skipped)}
    if not result.wasSuccessful() or result.skipped:
        raise AssertionError(baseline)
    original_observe = lab.observe
    def eager(path, mode, modules, root):
        return original_observe(path, "after_guard_eager_caller" if mode == "after" else mode, modules, root)
    ordering = check("BoundaryTests.test_leaf_patch", patch.object(lab, "observe", eager))
    original_load = lab.load_sources
    def no_leaf_guard():
        modules = original_load()
        # Remove new leaf guard behavior while retaining post-patch sensitive patterns.
        # The old guard's globals are rebound to the post-patch constants.
        import types
        old = modules["before"]._guard_file
        modules["after"]._guard_file = types.FunctionType(old.__code__, modules["after"].__dict__)
        return modules
    guard = check("BoundaryTests.test_leaf_patch", patch.object(lab, "load_sources", no_leaf_guard))
    for observed in (ordering, guard):
        if observed["failures"] < 1 or observed["errors"] or observed["skips"]:
            raise AssertionError(observed)
    return {"baseline": baseline, "faults": {"eager_resolution": ordering, "leaf_guard_removed": guard}}


if __name__ == "__main__":
    report = run_checks()
    (lab.ROOT / "artifacts").mkdir(exist_ok=True)
    (lab.ROOT / "artifacts/checks.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))
