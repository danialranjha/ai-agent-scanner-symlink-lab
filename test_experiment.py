import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import experiment as lab


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = lab.run()
        cls.rows = {(r["case"], r["mode"]): r for r in cls.result["rows"]}

    def test_leaf_patch(self):
        for case in ("relative_leaf", "absolute_leaf", "chained_leaf"):
            with self.subTest(case=case):
                self.assertEqual(self.rows[case, "before"]["read_hex"], lab.MARKER.hex())
                self.assertEqual(self.rows[case, "after"]["status"], "GUARD_REJECTED")
                self.assertIsNone(self.rows[case, "after"]["read_hex"])

    def test_regular_twin(self):
        for mode in lab.MODES:
            self.assertEqual(self.rows["regular", mode]["status"], "READ")
            self.assertEqual(self.rows["regular", mode]["read_hex"], lab.MARKER.hex())

    def test_ordering_ablation(self):
        row = self.rows["relative_leaf", "after_guard_eager_caller"]
        self.assertEqual(row["read_hex"], lab.MARKER.hex())
        guard = next(t for t in row["trace"] if t["stage"] == "guard_input")
        self.assertFalse(guard["leaf_is_symlink"])
        self.assertEqual(guard["path"], "data/note.txt")

    def test_parent_link_limit(self):
        for mode in lab.MODES:
            self.assertEqual(self.rows["parent_link", mode]["read_hex"], lab.MARKER.hex())

    def test_missing_and_dangling(self):
        for case in ("missing", "dangling_leaf"):
            for mode in lab.MODES:
                row = self.rows[case, mode]
                self.assertEqual(row["status"], "NOT_FOUND")
                self.assertIsNone(row["read_hex"])
                self.assertNotIn("guard_input", [t["stage"] for t in row["trace"]])

    def test_sensitive_and_separate_denylist_change(self):
        for mode in lab.MODES:
            self.assertEqual(self.rows["sensitive_name", mode]["status"], "GUARD_REJECTED")
        self.assertEqual(self.rows["secret_env", "before"]["read_hex"], lab.MARKER.hex())
        for mode in lab.MODES[1:]:
            self.assertEqual(self.rows["secret_env", mode]["status"], "GUARD_REJECTED")

    def test_after_checks_original_leaf(self):
        row = self.rows["relative_leaf", "after"]
        self.assertEqual([t["stage"] for t in row["trace"]], ["supplied", "guard_input"])
        self.assertTrue(row["trace"][-1]["leaf_is_symlink"])

    def test_complete_matrix(self):
        self.assertEqual(len(self.rows), 27)
        self.assertEqual(set(self.rows), {(c,m) for c in lab.SCENARIOS for m in lab.MODES})
        for row in self.rows.values():
            self.assertEqual(row["read_hex"] is not None, row["status"] == "READ")

    def test_determinism_and_cleanup(self):
        before = set(lab.ROOT.glob("fixture-*"))
        self.assertEqual(lab.run(), self.result)
        self.assertEqual(set(lab.ROOT.glob("fixture-*")), before)

    def test_source_identity_and_policy_unchanged(self):
        modules = lab.load_sources()
        for module in modules.values():
            self.assertEqual(module.MAX_FILE_BYTES, 2097152)
            self.assertIn(Path("/private"), module._SYSTEM_DIRS)
            self.assertIn(Path("/etc"), module._SYSTEM_DIRS)


if __name__ == "__main__":
    unittest.main()
