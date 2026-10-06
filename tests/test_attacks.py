from __future__ import annotations

import unittest
from pathlib import Path

from attacks.run_attacks import ATTACK_NAMES, run_suite
from tests.helpers import ALGORITHMS


class AttackSuiteTests(unittest.TestCase):
    def test_all_required_attacks_have_expected_outcomes_in_both_modes(self):
        data_root = Path(__file__).resolve().parents[1] / "data"
        for name in ALGORITHMS:
            with self.subTest(name=name):
                report = run_suite(name, data_root)
                self.assertTrue(report["passed"], report)
                self.assertEqual(set(report["outcomes"]), set(ATTACK_NAMES))


if __name__ == "__main__":
    unittest.main()
