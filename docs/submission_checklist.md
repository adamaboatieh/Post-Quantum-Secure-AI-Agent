# Submission Evidence Checklist

Completion is the original signed-agent research assignment: two signature
modes, independent authorization/freshness/replay, adversarial evidence,
benchmarks, later request verification, and a clear report/presentation/demo.

| Deliverable | Evidence | Final status |
|---|---|---|
| Ed25519 and ML-DSA-44 signed `read_file` pipeline | Shared signing interfaces, canonical envelope, security tests | Staged and actual target suites: 83 tests passed; target 3.675 s, no failures/skips |
| Seven required attack scenarios in both modes | `attacks.run_attacks --algorithm both` | All seven passed in each mode |
| Crypto performance through 10,000 requests | Original `results/benchmark_results.json`, CSV and SVGs | Completed; preserved |
| Actual Gemini end-to-end comparison | `results/llm_e2e/20261006T103303092153Z-7d2cda94/` | Completed: 20 measured pairs, 1 warm-up pair, 84 API calls, no failures |
| Bounded real Gemini injection examples in both modes | [Recorded live run](../results/live_injection/live_injection_20261006T111819_769178Z_1468a3ef0e684eef9bef372bdcfd5f2b.md) | Completed: 10 calls, no failures/retries; actual observations reported |
| Retained request signature re-verification after process exit | Both audited Gemini CLI workflows; separate `server.audit` processes and outside key pins | Passed in both modes; no reexecution |
| Research report and methodology | README; results, security, architecture, threat model, benchmark docs | Updated with completed measurements and live evidence |
| Submission presentation | `presentation/Post_Quantum_Secure_AI_Agent_Presentation_Submission.pptx` | All 10 slides rendered and visually inspected; package/layout/font/table/chart/workbook/reimport checks passed |
| Fifteen-minute demo | `docs/demo_script.md` | Normal live commands, attacks, and historical verification rehearsed; no human timed talk recorded |
| Final repository integrity and secrets checks | AST syntax, whitespace, preserved-file hashes, and file/deck secret scan | Passed with the recorded artifact formatting exception below; secrets/runtime ignored, original artifacts and user report preserved |
| Final reviewed commit and remote delivery | Git history, `origin/feat/assignment-rebuild`, and publication handoff | Publication authorized without merging; verify the published commit against the handoff |

The technical assignment deliverables are complete. A human timed rehearsal
remains. Publication of `feat/assignment-rebuild` is authorized without merging.
Native PowerPoint
application opening has not been recorded; package validation, full-slide
render inspection, and reimport were completed. Keep credentials, private keys,
local audit databases, and runtime outputs out of the commit. Preserve the
user's report and original crypto artifacts.

## Files included in this publication

Adapted existing files:

- `README.md`
- `data/report.txt` (the user's existing edits, preserved)
- `docs/architecture.md`
- `docs/demo_script.md`
- `docs/results.md`
- `docs/security_analysis.md`
- `docs/threat_model.md`
- `src/agent/backends.py`
- `src/agent/cli.py`
- `src/server/tool_server.py`

Added files:

- `benchmarks/run_llm_benchmark.py`
- `docs/llm_benchmark.md`
- `docs/submission_checklist.md`
- `src/server/audit.py`
- `tests/test_audit.py`
- `attacks/run_live_injection.py`
- `tests/test_live_injection.py`
- `tests/test_live_summary.py`
- `tests/test_llm_benchmark.py`
- `presentation/Post_Quantum_Secure_AI_Agent_Presentation_Submission.pptx`
- `results/live_injection/live_injection_20261006T111819_769178Z_1468a3ef0e684eef9bef372bdcfd5f2b.json`
- `results/live_injection/live_injection_20261006T111819_769178Z_1468a3ef0e684eef9bef372bdcfd5f2b.md`
- `results/llm_e2e/20261006T102706Z-smoke/llm_e2e_results.json`
- `results/llm_e2e/20261006T102706Z-smoke/llm_e2e_results.md`
- `results/llm_e2e/20261006T102706Z-smoke/llm_e2e_samples.csv`
- `results/llm_e2e/20261006T102706Z-smoke/llm_e2e_summary.csv`
- `results/llm_e2e/20261006T103303092153Z-7d2cda94/llm_e2e_results.json`
- `results/llm_e2e/20261006T103303092153Z-7d2cda94/llm_e2e_results.md`
- `results/llm_e2e/20261006T103303092153Z-7d2cda94/llm_e2e_samples.csv`
- `results/llm_e2e/20261006T103303092153Z-7d2cda94/llm_e2e_summary.csv`

Removed at the user's request:

- `presentation/Post_Quantum_Secure_AI_Agent_Presentation_Final.pptx`

The superseded deck remains recoverable from Git history. Original crypto
benchmark code/results/charts, earlier live benchmark artifacts, and the user's
report bytes were preserved. The report differs from the previous commit
because it includes the user's edits; closeout and publication did not rewrite
it. Submission chart and embedded-workbook parts
preserve the original bytes; one native table and two native charts remain
editable. Ignored audit databases contain runtime history and are excluded
from the file manifest and commit.

AST syntax checks covered 43 Python files. Before publication cleanup, SHA-256
checks confirmed all 55 baseline files outside the nine closeout adaptations
were unchanged. After the explicitly authorized old-deck removal, the remaining
54 protected baseline files were preserved, including both historical benchmark
runs, original crypto code/artifacts, and the user's report. The secret scan checked non-ignored
tracked/untracked files and the final deck's uncompressed XML. One private-key
header in a unit-test assertion was inspected as a harmless check, not key
material. The future Gateway repository remained clean and unmodified.

The staged whitespace check found one extra blank line at the end of
`results/llm_e2e/20261006T103303092153Z-7d2cda94/llm_e2e_results.md`.
This harmless generated-report style exception is accepted to preserve the
authentic artifact bytes. All other files pass the strict whitespace check;
the report passes with only the blank-at-EOF rule disabled.

Known boundaries remain visible in the report: authentication does not establish
semantic safety; stored audit keys require outside trust; outcomes/logs are
not authenticated; historical benchmark audit I/O is excluded; the modest
live sample is descriptive rather than a deployment guarantee. Optional gateway,
MCP, distributed infrastructure, or production certification is not required
to complete this assignment.
