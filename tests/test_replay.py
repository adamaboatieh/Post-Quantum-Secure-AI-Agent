from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from server.replay import ReplayStore
from server.tool_server import RequestRejected
from tests.helpers import ALGORITHMS, FIXED_NOW, build_stack


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "report.txt").write_text("fixture", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_replay_expired_and_future_requests_in_both_modes(self):
        for name in ALGORITHMS:
            with self.subTest(name=name):
                _signer, signing, _policy, replay, server, agent = build_stack(name, self.root)
                try:
                    envelope = agent.create_envelope("Read report.txt", now=FIXED_NOW)
                    server.execute(envelope, now=FIXED_NOW)
                    with self.assertRaises(RequestRejected) as context:
                        server.execute(envelope, now=FIXED_NOW)
                    self.assertEqual(context.exception.code, "REPLAY_DETECTED")

                    expired = signing.create_envelope(
                        "read_file", {"path": "report.txt"}, now=FIXED_NOW - timedelta(minutes=2)
                    )
                    with self.assertRaises(RequestRejected) as context:
                        server.execute(expired, now=FIXED_NOW)
                    self.assertEqual(context.exception.code, "EXPIRED")

                    future = signing.create_envelope(
                        "read_file", {"path": "report.txt"}, now=FIXED_NOW + timedelta(minutes=2)
                    )
                    with self.assertRaises(RequestRejected) as context:
                        server.execute(future, now=FIXED_NOW)
                    self.assertEqual(context.exception.code, "NOT_YET_VALID")
                finally:
                    replay.close()

    def test_request_id_and_nonce_are_independently_unique(self):
        store = ReplayStore()
        try:
            self.assertTrue(store.claim(agent_id="a", request_id="r1", nonce="n1"))
            self.assertFalse(store.claim(agent_id="a", request_id="r1", nonce="n2"))
            self.assertFalse(store.claim(agent_id="a", request_id="r2", nonce="n1"))
        finally:
            store.close()

    def test_replay_claim_survives_restart(self):
        database = self.root / "replay.sqlite3"
        first = ReplayStore(database)
        self.assertTrue(first.claim(agent_id="a", request_id="r", nonce="n"))
        first.close()
        second = ReplayStore(database)
        try:
            self.assertFalse(second.claim(agent_id="a", request_id="r", nonce="n"))
        finally:
            second.close()


if __name__ == "__main__":
    unittest.main()
