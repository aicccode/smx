"""The Python demo client against hostile local servers on ephemeral ports."""

from __future__ import annotations

import contextlib
import http.server
import importlib.util
import io
import json
import os
import socket
import threading
import time
import unittest
from pathlib import Path
from typing import ClassVar
from unittest import mock

from smx import (
    SM4,
    hex_to_bytes,
    sm2_check_sa,
    sm2_decode_point,
    sm2_gen_key_pair,
    sm2_get_sb,
)
from smx.hexutil import hex_to_int

MAIN = Path(__file__).resolve().parents[2] / "demo" / "client-python" / "main.py"
spec = importlib.util.spec_from_file_location("demo_client_main", MAIN)
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, body):
        if isinstance(body, str):
            body = body.encode("utf-8", "surrogatepass")
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        return json.loads(self.rfile.read(int(self.headers["Content-Length"])))


class ExchangeServer(Handler):
    """A working B side: an impostor, unless the client pins some other key."""

    state: ClassVar[dict] = {}
    success: object = True
    server_plaintext = "reply"

    def do_POST(self):
        request = self.body()
        cls = type(self)
        decode = sm2_decode_point
        if self.path.endswith("init"):
            private, public = cls.state["key"]
            random_private, random_public = sm2_gen_key_pair()
            result = sm2_get_sb(
                request["keyLen"],
                decode(request["pA"]),
                decode(request["Ra"]),
                decode(public),
                hex_to_int(private),
                decode(random_public),
                hex_to_int(random_private),
                request["IDa"],
                "server",
            )
            cls.state.update(
                result=result, ra=decode(request["Ra"]), rb=decode(random_public)
            )
            reply = {
                "sessionId": "s",
                "pB": public,
                "Rb": random_public,
                "IDb": "server",
                "Sb": result.sb,
            }
        elif self.path.endswith("confirm"):
            result = cls.state["result"]
            valid = sm2_check_sa(
                result.v,
                result.za,
                result.zb,
                cls.state["ra"],
                cls.state["rb"],
                hex_to_bytes(request["Sa"]),
            )
            reply = {"success": cls.success if valid else False}
        else:
            cipher = SM4()
            cipher.set_key(hex_to_bytes(cls.state["result"].kb), bytes(16))
            cls.state["stolen"] = cipher.decrypt(request["clientCiphertext"])
            reply = {
                "clientDecryptMatch": True,
                "serverCiphertext": cipher.encrypt(cls.server_plaintext),
                "serverPlaintext": cls.server_plaintext,
            }
        self.send(json.dumps(reply))


class ClientTest(unittest.TestCase):
    def serve(self, handler):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server.server_address[1]

    def raw_server(self, responder):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(5)
        self.addCleanup(listener.close)

        def loop():
            while True:
                try:
                    connection, _ = listener.accept()
                except OSError:
                    return
                connection.recv(65536)
                threading.Thread(
                    target=responder, args=(connection,), daemon=True
                ).start()

        threading.Thread(target=loop, daemon=True).start()
        return listener.getsockname()[1]

    def run_demo(self, port, pin=None, deadline=None):
        environment = {k: v for k, v in os.environ.items() if k != demo.PIN_VARIABLE}
        if pin is not None:
            environment[demo.PIN_VARIABLE] = pin
        out, err = io.StringIO(), io.StringIO()
        patches = [
            mock.patch.object(demo, "SERVER_URL", f"http://127.0.0.1:{port}"),
            mock.patch.dict(os.environ, environment, clear=True),
        ]
        if deadline is not None:
            patches.append(
                mock.patch.object(demo, "REQUEST_DEADLINE_SECONDS", deadline)
            )
        for patch in patches:
            patch.start()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = demo.main()
        for patch in patches:
            patch.stop()
        return code, out.getvalue(), err.getvalue()

    def exchange_server(self, **attributes):
        key = sm2_gen_key_pair()
        namespace = {"state": {"key": key}, **attributes}
        return type("Server", (ExchangeServer,), namespace), key

    def test_unpinned_run_warns_and_never_says_secure(self):
        server, _ = self.exchange_server()
        code, out, _ = self.run_demo(self.serve(server))
        self.assertEqual(code, 0)
        self.assertIn("UNAUTHENTICATED", out)
        self.assertNotIn("secure", out.lower())

    def test_correct_pin_passes(self):
        server, (_, public) = self.exchange_server()
        code, out, _ = self.run_demo(self.serve(server), pin=public)
        self.assertEqual(code, 0)
        self.assertNotIn("UNAUTHENTICATED", out)
        self.assertIn("pinned", out)

    def test_pin_accepts_either_hex_case(self):
        server, (_, public) = self.exchange_server()
        self.assertEqual(self.run_demo(self.serve(server), pin=public.upper())[0], 0)

    def test_wrong_pin_stops_an_impostor_before_any_traffic(self):
        server, _ = self.exchange_server()
        _, other = sm2_gen_key_pair()
        code, _, err = self.run_demo(self.serve(server), pin=other)
        self.assertEqual(code, 1)
        self.assertIn("does not match", err)
        self.assertNotIn("stolen", server.state)

    def test_invalid_pin_is_a_failure(self):
        server, _ = self.exchange_server()
        for bad in ("", "04", "zz" * 65):
            code, _, _ = self.run_demo(self.serve(server), pin=bad)
            self.assertEqual(code, 1, bad)

    def test_only_boolean_true_counts_as_confirmation(self):
        for value in ("false", "true", 1, [1], {"a": 1}, None):
            server, _ = self.exchange_server(success=value)
            code, _, err = self.run_demo(self.serve(server))
            self.assertEqual(code, 1, repr(value))
            self.assertIn("confirmation failed", err)
            self.assertNotIn("stolen", server.state)

    def test_control_characters_are_stripped_from_server_text(self):
        hostile = "\x1b]0;pwned\x07\x1b[2Jtext\u202e\ud800"
        server, _ = self.exchange_server(server_plaintext="\x1b[2Jreply\x07")
        _, out, _ = self.run_demo(self.serve(server))
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

        class Escape(Handler):
            def do_POST(self):
                self.body()
                self.send(hostile.encode("utf-8", "surrogatepass"))

        code, out, err = self.run_demo(self.serve(Escape))
        self.assertEqual(code, 1)
        for text in (out, err):
            self.assertNotIn("\x1b", text)
            self.assertNotIn("\x07", text)

        self.assertEqual(
            demo.printable("a\x1b\n\u202e\ud800"), "a\\x1b\\x0a\\x202e\\xd800"
        )

    def test_malformed_responses_fail_cleanly(self):
        for body in (
            "[" * 200000,
            '{"a":' * 200000,
            "not json",
            "[]",
            "5",
            "null",
            "{}",
            '{"pB":5}',
            '{"pB":null,"Rb":[],"IDb":{},"Sb":1,"sessionId":2}',
            b"\xff\xfe",
        ):

            class Reply(Handler):
                payload = body

                def do_POST(self):
                    self.body()
                    self.send(self.payload)

            code, _, err = self.run_demo(self.serve(Reply))
            self.assertEqual(code, 1, repr(body)[:40])
            self.assertIn("Invalid server response", err, repr(body)[:40])

    def test_broken_http_fails_cleanly(self):
        for reply in (
            b"garbage line\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}",
            b"",
            b"HTTP/1.1 500 Nope\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/\r\nContent-Length: 0\r\n\r\n",
        ):

            def responder(connection, data=reply):
                connection.sendall(data)
                connection.close()

            code, _, _ = self.run_demo(self.raw_server(responder))
            self.assertEqual(code, 1, reply)

    def test_response_size_is_capped(self):
        size = demo.MAX_RESPONSE_BYTES + 10

        class Large(Handler):
            def do_POST(self):
                self.body()
                self.send(b" " * size)

        code, _, err = self.run_demo(self.serve(Large))
        self.assertEqual(code, 1)
        self.assertIn("Invalid server response", err)

    def test_slow_drip_hits_the_overall_deadline(self):
        def body_drip(connection):
            with contextlib.suppress(OSError):
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2000000\r\n\r\n"
                )
                for _ in range(200):
                    connection.sendall(b"{")
                    time.sleep(0.05)

        def header_drip(connection):
            with contextlib.suppress(OSError):
                connection.sendall(b"HTTP/1.1 200 OK\r\n")
                for _ in range(200):
                    connection.sendall(b"X-A: b\r\n")
                    time.sleep(0.05)

        for responder in (body_drip, header_drip):
            started = time.monotonic()
            code, _, err = self.run_demo(self.raw_server(responder), deadline=0.5)
            self.assertEqual(code, 1)
            self.assertLess(time.monotonic() - started, 5)
            self.assertIn("in time", err)

    def test_no_private_key_or_session_key_is_printed(self):
        server, _ = self.exchange_server()
        _, out, err = self.run_demo(self.serve(server))
        kb = server.state["result"].kb
        self.assertNotIn(kb, out + err)
        self.assertNotIn(kb.upper(), (out + err).upper())
        self.assertNotIn("private key", (out + err).lower())


if __name__ == "__main__":
    unittest.main()
