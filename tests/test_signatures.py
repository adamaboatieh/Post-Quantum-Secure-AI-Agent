from __future__ import annotations

import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from server.tool_server import RequestRejected, ToolServer, TrustedKey
from signing.canonical import CanonicalizationError, canonical_json
from signing.schemes import get_scheme
from tests.helpers import ALGORITHMS, FIXED_NOW, build_stack


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "report.txt").write_text("classical and post-quantum demo", encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def test_sign_verify_and_invalid_message_in_both_modes(self):
        expected = {
            "ed25519": (32, 32, 64),
            "ml-dsa": (1312, 32, 2420),
        }
        for name in ALGORITHMS:
            with self.subTest(name=name):
                scheme = get_scheme(name)
                signer = scheme.generate()
                verifier = scheme.verifier(signer.public_key_bytes())
                signature = signer.sign(b"message")
                self.assertTrue(verifier.verify(b"message", signature))
                self.assertFalse(verifier.verify(b"changed", signature))
                self.assertEqual(
                    (len(signer.public_key_bytes()), len(signer.private_key_bytes()), len(signature)),
                    expected[name],
                )

    def test_valid_envelope_executes_in_both_modes(self):
        for name in ALGORITHMS:
            with self.subTest(name=name):
                _signer, _signing, _policy, replay, server, agent = build_stack(name, self.root)
                try:
                    result = server.execute(
                        agent.create_envelope("Read report.txt and summarize it.", now=FIXED_NOW),
                        now=FIXED_NOW,
                    )
                    self.assertEqual(result["status"], "completed")
                    self.assertEqual(result["result"]["content"], "classical and post-quantum demo")
                finally:
                    replay.close()

    def test_tampering_forgery_wrong_key_and_unauthorized_action(self):
        for name in ALGORITHMS:
            with self.subTest(name=name):
                signer, signing, policy, replay, server, agent = build_stack(name, self.root)
                try:
                    envelope = agent.create_envelope("Read report.txt", now=FIXED_NOW)
                    tampered = deepcopy(envelope)
                    tampered["payload"]["arguments"]["path"] = "other.txt"
                    with self.assertRaises(RequestRejected) as context:
                        server.execute(tampered, now=FIXED_NOW)
                    self.assertEqual(context.exception.code, "INVALID_SIGNATURE")

                    forged = deepcopy(envelope)
                    forged["signature"] = "Zm9yZ2Vk"
                    with self.assertRaises(RequestRejected) as context:
                        server.execute(forged, now=FIXED_NOW)
                    self.assertEqual(context.exception.code, "INVALID_SIGNATURE")

                    other = get_scheme(name).generate()
                    wrong_server = ToolServer(
                        {signing.key_id: TrustedKey(signing.agent_id, signer.algorithm, other.public_key_bytes())},
                        replay,
                        policy,
                    )
                    with self.assertRaises(RequestRejected) as context:
                        wrong_server.execute(envelope, now=FIXED_NOW)
                    self.assertEqual(context.exception.code, "INVALID_SIGNATURE")

                    forbidden = signing.create_envelope(
                        "delete_database", {"database": "demo"}, now=FIXED_NOW
                    )
                    with self.assertRaises(RequestRejected) as context:
                        server.execute(forbidden, now=FIXED_NOW)
                    self.assertEqual(context.exception.code, "AUTHORIZATION_DENIED")
                    self.assertTrue(context.exception.verified)
                finally:
                    replay.close()

    def test_canonicalization_is_stable_and_rejects_floats(self):
        self.assertEqual(canonical_json({"a": 1, "b": 2}), canonical_json({"b": 2, "a": 1}))
        with self.assertRaises(CanonicalizationError):
            canonical_json({"value": 1.5})

    def test_malformed_envelope_is_rejected_in_both_modes(self):
        for name in ALGORITHMS:
            with self.subTest(name=name):
                _signer, _signing, _policy, replay, server, _agent = build_stack(name, self.root)
                try:
                    for malformed in ({}, {"payload": {}}, {"payload": {}, "signature": ""}):
                        with self.assertRaises(RequestRejected) as context:
                            server.execute(malformed, now=FIXED_NOW)
                        self.assertEqual(context.exception.code, "MALFORMED_REQUEST")
                finally:
                    replay.close()


if __name__ == "__main__":
    unittest.main()
