from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from server.http_server import create_http_server
from signing.canonical import canonical_json
from tests.helpers import ALGORITHMS, build_stack


class HTTPTests(unittest.TestCase):
    def test_local_service_executes_then_rejects_replay_in_both_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "report.txt").write_text("HTTP fixture", encoding="utf-8")
            for name in ALGORITHMS:
                with self.subTest(name=name):
                    _signer, _signing, _policy, replay, service, agent = build_stack(name, root)
                    http = create_http_server(service)
                    thread = threading.Thread(target=http.serve_forever, daemon=True)
                    thread.start()
                    try:
                        envelope = agent.create_envelope("Read report.txt")
                        request = Request(
                            f"http://127.0.0.1:{http.server_port}/tool",
                            data=canonical_json(envelope),
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        )
                        with urlopen(request, timeout=5) as response:
                            body = json.loads(response.read())
                        self.assertEqual(body["result"]["content"], "HTTP fixture")
                        with self.assertRaises(HTTPError) as context:
                            urlopen(request, timeout=5)
                        self.assertEqual(context.exception.code, 409)
                    finally:
                        http.shutdown()
                        http.server_close()
                        thread.join(timeout=5)
                        replay.close()


if __name__ == "__main__":
    unittest.main()
