"""Durable public audit evidence, historical pinning, and failure semantics."""

from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.cli import main as demo_main, run_demo
from server.audit import AuditStore, AuditUnavailable, main as audit_main, public_key_sha256, verify_history
from server.tool_server import RequestRejected, ToolServer
from signing.encoding import b64url_decode, b64url_encode
from tools.file_access import FileReadDenied
from tests.helpers import ALGORITHMS, FIXED_NOW, build_stack


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.file_content = "FILE_CONTENT_MUST_NOT_BE_RETAINED_IN_AUDIT_7d3e9389"
        (self.root / "report.txt").write_text(self.file_content, encoding="utf-8")

    def stack(self, algorithm="ed25519"):
        signer, signing, policy, replay, _server, agent = build_stack(algorithm, self.root)
        audit_path = self.root / f"{algorithm}.sqlite3"
        audit = AuditStore(audit_path)
        server = ToolServer(_server._trusted_keys, replay, policy, audit_store=audit)
        self.addCleanup(replay.close)
        self.addCleanup(audit.close)
        envelope = signing.create_envelope("read_file", {"path": "report.txt"}, now=FIXED_NOW)
        return signer, signing, server, agent, audit, audit_path, envelope

    def mutate(self, database, field, value):
        # Tests alter copies of public fixtures; production verification is read-only.
        connection = sqlite3.connect(database)
        try:
            with connection:
                connection.execute(f"UPDATE action_audit SET {field} = ?", (value,))
        finally:
            connection.close()

    def test_history_survives_reload_without_live_keys_for_both_algorithms(self):
        for algorithm in ALGORITHMS:
            with self.subTest(algorithm=algorithm):
                signer, signing, server, agent, audit, database, envelope = self.stack(algorithm)
                fingerprint = public_key_sha256(signer.public_key_bytes())
                response = server.execute(envelope, now=FIXED_NOW)
                self.assertEqual(response["status"], "completed")
                audit.close()
                del signer, signing, server, agent
                before = database.read_bytes()
                records = verify_history(
                    database, request_id=envelope["payload"]["request_id"],
                    expected_public_key_sha256=fingerprint,
                )
                self.assertEqual(database.read_bytes(), before)
                self.assertEqual(len(records), 1)
                record = records[0]
                self.assertTrue(record["signature_valid"])
                self.assertTrue(record["binding_consistent"])
                self.assertTrue(record["verification_passed"])
                self.assertTrue(record["key_pinned"])
                self.assertEqual(record["recorded_execution_state"], "completed")
                self.assertIsNotNone(record["finalized_at"])
                self.assertEqual(record["log_integrity"], "not_authenticated")
                self.assertEqual(record["outcome_integrity"], "not_authenticated")
                self.assertTrue(record["historical_only"])

    def test_envelope_is_committed_before_invocation_and_contains_public_evidence_only(self):
        for algorithm in ALGORITHMS:
            with self.subTest(algorithm=algorithm):
                signer, _signing, server, _agent, audit, database, envelope = self.stack(algorithm)
                private_seed = signer.private_key_bytes()

                def observe_prepared(*_args, **_kwargs):
                    self.assertEqual(verify_history(database)[0]["recorded_execution_state"], "prepared")
                    return {"content": self.file_content}

                with patch("server.tool_server.execute_tool", side_effect=observe_prepared) as invoke:
                    server.execute(envelope, now=FIXED_NOW)
                invoke.assert_called_once()
                audit.close()
                persisted = database.read_bytes()
                self.assertNotIn(self.file_content.encode("utf-8"), persisted)
                self.assertNotIn(private_seed, persisted)
                self.assertNotIn(b64url_encode(private_seed).encode("ascii"), persisted)
                self.assertNotIn(b"PRIVATE KEY", persisted)
                connection = sqlite3.connect(database)
                try:
                    row = connection.execute("SELECT envelope_json, public_key FROM action_audit").fetchone()
                finally:
                    connection.close()
                self.assertEqual(json.loads(row[0]), envelope)
                self.assertEqual(b64url_decode(row[1]), signer.public_key_bytes())

    def test_altered_payload_or_signature_fails_for_both_algorithms(self):
        for algorithm in ALGORITHMS:
            for target in ("payload", "signature"):
                with self.subTest(algorithm=algorithm, target=target):
                    # Each alteration uses a fresh temporary path and independent request.
                    database = self.root / f"tamper-{algorithm}-{target}.sqlite3"
                    signer, signing, _policy, replay, server, _agent = build_stack(algorithm, self.root)
                    self.addCleanup(replay.close)
                    with AuditStore(database) as audit:
                        server._audit_store = audit
                        envelope = signing.create_envelope("read_file", {"path": "report.txt"}, now=FIXED_NOW)
                        server.execute(envelope, now=FIXED_NOW)
                    if target == "payload":
                        envelope["payload"]["arguments"]["path"] = "different.txt"
                    else:
                        signature = bytearray(b64url_decode(envelope["signature"]))
                        signature[0] ^= 1
                        envelope["signature"] = b64url_encode(bytes(signature))
                    self.mutate(database, "envelope_json", json.dumps(envelope))
                    record = verify_history(database)[0]
                    self.assertFalse(record["signature_valid"])
                    self.assertFalse(record["verification_passed"])

    def test_pin_mismatch_does_not_mislabel_valid_signature(self):
        for algorithm in ALGORITHMS:
            with self.subTest(algorithm=algorithm):
                _signer, _signing, server, _agent, _audit, database, envelope = self.stack(algorithm)
                server.execute(envelope, now=FIXED_NOW)
                record = verify_history(database, expected_public_key_sha256="0" * 64)[0]
                self.assertTrue(record["signature_valid"])
                self.assertFalse(record["pin_matches"])
                self.assertFalse(record["key_pinned"])
                self.assertFalse(record["verification_passed"])
                unpinned = verify_history(database)[0]
                self.assertTrue(unpinned["signature_valid"])
                self.assertIsNone(unpinned["pin_matches"])
                self.assertFalse(unpinned["key_pinned"])
                self.assertEqual(unpinned["identity_trust"], "recorded_key_only")

    def test_outcome_is_not_signature_proof_and_binding_changes_are_detected(self):
        _signer, _signing, server, _agent, _audit, database, envelope = self.stack()
        server.execute(envelope, now=FIXED_NOW)
        self.mutate(database, "execution_state", "denied")
        record = verify_history(database)[0]
        self.assertTrue(record["signature_valid"])
        self.assertEqual(record["recorded_execution_state"], "denied")
        self.assertEqual(record["outcome_integrity"], "not_authenticated")
        self.mutate(database, "agent_id", "different-agent")
        record = verify_history(database)[0]
        self.assertTrue(record["signature_valid"])
        self.assertFalse(record["binding_consistent"])
        self.assertFalse(record["verification_passed"])

    def test_replacing_recorded_key_and_signature_requires_independent_pin(self):
        signer, _signing, server, _agent, _audit, database, envelope = self.stack()
        pin = public_key_sha256(signer.public_key_bytes())
        server.execute(envelope, now=FIXED_NOW)
        replacement, _signing2, _policy2, replay2, _server2, _agent2 = build_stack("ed25519", self.root)
        self.addCleanup(replay2.close)
        from signing.canonical import signing_bytes
        envelope["signature"] = b64url_encode(replacement.sign(signing_bytes(envelope["payload"])))
        self.mutate(database, "envelope_json", json.dumps(envelope))
        self.mutate(database, "public_key", b64url_encode(replacement.public_key_bytes()))
        self.assertTrue(verify_history(database)[0]["signature_valid"])
        record = verify_history(database, expected_public_key_sha256=pin)[0]
        self.assertTrue(record["signature_valid"])
        self.assertFalse(record["verification_passed"])
        self.assertFalse(record["pin_matches"])

    def test_initial_audit_write_failure_blocks_tool_invocation(self):
        _signer, _signing, server, _agent, audit, _database, envelope = self.stack()
        audit.close()
        with patch("server.tool_server.execute_tool") as invoke:
            with self.assertRaises(RequestRejected) as raised:
                server.execute(envelope, now=FIXED_NOW)
        invoke.assert_not_called()
        self.assertEqual(raised.exception.code, "AUDIT_UNAVAILABLE")
        self.assertIn("before tool invocation", str(raised.exception))
        self.assertTrue(raised.exception.verified)

    def test_sqlite_write_failure_blocks_tool_and_is_sanitized(self):
        _signer, _signing, server, _agent, audit, _database, envelope = self.stack()
        # A real read-only connection failure must be wrapped, not leaked.
        audit._connection.execute("PRAGMA query_only = ON")
        with patch("server.tool_server.execute_tool") as invoke:
            with self.assertRaises(RequestRejected) as raised:
                server.execute(envelope, now=FIXED_NOW)
        invoke.assert_not_called()
        self.assertEqual(raised.exception.code, "AUDIT_UNAVAILABLE")
        self.assertNotIn("readonly", str(raised.exception))

    def test_outcome_failure_reports_already_invoked_and_never_retries(self):
        for observed in ("completed", "denied"):
            with self.subTest(observed=observed):
                _signer, _signing, server, _agent, audit, database, envelope = self.stack()
                result = {"content": self.file_content} if observed == "completed" else None
                error = None if observed == "completed" else FileReadDenied("fixture denial")
                with patch.object(audit, "finalize", side_effect=AuditUnavailable("fixture diagnostic")):
                    with patch("server.tool_server.execute_tool", return_value=result, side_effect=error) as invoke:
                        with self.assertRaises(RequestRejected) as raised:
                            server.execute(envelope, now=FIXED_NOW)
                invoke.assert_called_once()
                self.assertEqual(raised.exception.code, "AUDIT_OUTCOME_UNAVAILABLE")
                self.assertIn("tool was invoked", str(raised.exception))
                self.assertIn(f"observed outcome: {observed}", str(raised.exception))
                self.assertIn("do not retry", str(raised.exception))
                self.assertEqual(verify_history(database)[-1]["recorded_execution_state"], "prepared")
                audit.close()

    def test_denied_and_unexpected_execution_are_finalized_without_content(self):
        for error, expected in ((FileReadDenied("denied"), "denied"), (RuntimeError("detail"), "uncertain")):
            with self.subTest(expected=expected):
                _signer, _signing, server, _agent, audit, database, envelope = self.stack()
                with patch("server.tool_server.execute_tool", side_effect=error):
                    with self.assertRaises(RequestRejected):
                        server.execute(envelope, now=FIXED_NOW)
                self.assertEqual(verify_history(database)[-1]["recorded_execution_state"], expected)
                audit.close()

    def test_rejected_request_has_no_audit_record(self):
        _signer, _signing, server, _agent, _audit, database, envelope = self.stack()
        envelope["payload"]["arguments"]["path"] = "different.txt"
        with self.assertRaises(RequestRejected):
            server.execute(envelope, now=FIXED_NOW)
        self.assertEqual(verify_history(database), [])

    def test_missing_database_and_invalid_pin_do_not_create_a_file(self):
        missing = self.root / "absent.sqlite3"
        with self.assertRaises(AuditUnavailable):
            verify_history(missing)
        self.assertFalse(missing.exists())
        with self.assertRaises(ValueError):
            verify_history(missing, expected_public_key_sha256="not-a-fingerprint")
        self.assertFalse(missing.exists())

    def test_malformed_history_is_rejected_and_schema_failure_is_sanitized(self):
        _signer, _signing, server, _agent, audit, database, envelope = self.stack()
        server.execute(envelope, now=FIXED_NOW)
        self.mutate(database, "envelope_json", "not JSON")
        self.assertFalse(verify_history(database)[0]["verification_passed"])
        audit.close()
        connection = sqlite3.connect(database)
        try:
            with connection:
                connection.execute("DROP TABLE action_audit")
                connection.execute("CREATE TABLE action_audit (different_field TEXT)")
                connection.execute("INSERT INTO action_audit VALUES ('malformed schema')")
        finally:
            connection.close()
        with self.assertRaises(AuditUnavailable) as raised:
            verify_history(database)
        self.assertEqual(str(raised.exception), "historical audit database cannot be read")

    def test_historical_cli_outputs_pin_status_and_fails_on_mismatch(self):
        signer, _signing, server, _agent, _audit, database, envelope = self.stack()
        server.execute(envelope, now=FIXED_NOW)
        for pin, expected_exit in ((public_key_sha256(signer.public_key_bytes()), None), ("0" * 64, 1)):
            with self.subTest(expected_exit=expected_exit):
                command = ["audit", "--database", str(database), "--request-id", envelope["payload"]["request_id"], "--public-key-sha256", pin]
                with patch("sys.argv", command), patch("sys.stdout", new_callable=io.StringIO) as output:
                    if expected_exit:
                        with self.assertRaises(SystemExit) as raised:
                            audit_main()
                        self.assertEqual(raised.exception.code, expected_exit)
                    else:
                        audit_main()
                record = json.loads(output.getvalue())["records"][0]
                self.assertEqual(record["key_pinned"], expected_exit is None)
                self.assertTrue(record["signature_valid"])

    def test_cli_enables_default_audit_and_can_skip_it(self):
        for arguments, expected in (([], Path("runtime/audit.sqlite3")), (["--no-audit"], None)):
            with self.subTest(arguments=arguments):
                with patch("sys.argv", ["demo", *arguments]), patch("agent.cli.run_demo", return_value={"summary_status": "local_preview"}) as demo:
                    with patch("sys.stdout", new_callable=io.StringIO):
                        demo_main()
                self.assertEqual(demo.call_args.kwargs["audit_db"], expected)

    def test_audited_demo_reports_independent_public_key_fingerprint(self):
        task = "Read report.txt and summarize it. MODEL_TASK_NOT_AUDITED_3299"
        database = self.root / "demo.sqlite3"
        report = run_demo(task, algorithm="ml-dsa", data_root=self.root, audit_db=database)
        self.assertEqual(report["audit_database"], str(database))
        record = verify_history(database, expected_public_key_sha256=report["audit_public_key_sha256"])[0]
        self.assertTrue(record["verification_passed"])
        self.assertEqual(record["request_id"], report["request_id"])
        self.assertNotIn(b"MODEL_TASK_NOT_AUDITED_3299", database.read_bytes())


if __name__ == "__main__":
    unittest.main()
