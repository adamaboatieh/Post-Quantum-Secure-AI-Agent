from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from benchmarks.run_benchmarks import percentile, run


class BenchmarkTests(unittest.TestCase):
    def test_percentile_uses_nearest_rank(self):
        self.assertEqual(percentile([1, 2, 3, 4, 5], 0.95), 5)

    def test_smoke_benchmark_writes_machine_readable_results(self):
        project = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            report = run(
                repetitions=20,
                scales=[1],
                data_root=project / "data",
                output_dir=Path(directory),
            )
            self.assertEqual([x["algorithm"] for x in report["algorithms"]], ["Ed25519", "ML-DSA-44"])
            for name in (
                "benchmark_results.json",
                "benchmark_summary.csv",
                "sign_latency.svg",
                "signature_size.svg",
            ):
                self.assertTrue((Path(directory) / name).is_file())


if __name__ == "__main__":
    unittest.main()
