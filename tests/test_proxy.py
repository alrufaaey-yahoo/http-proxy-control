import asyncio
import base64
import os
import socket
import tempfile
import unittest
from unittest.mock import patch

# Keep model-validation tests isolated from any system database.
os.environ.setdefault(
    "APP_DB", os.path.join(tempfile.gettempdir(), "http-proxy-control-test-suite.db")
)

from pydantic import ValidationError

from app.main import ListenerInput, ListenerUpdate
from app.proxy import ProxyRequestError, _parse_authority, listener_callback
from app.store import password_hash, password_matches


class PasswordTests(unittest.TestCase):
    def test_password_hash_verifies(self):
        encoded = password_hash("correct horse battery staple")
        self.assertTrue(password_matches("correct horse battery staple", encoded))
        self.assertFalse(password_matches("wrong password", encoded))

    def test_proxy_password_three_characters_is_accepted(self):
        listener = ListenerInput(port=3128, username="client", password="abc")
        self.assertFalse(listener.tls_enabled)
        self.assertEqual(listener.password, "abc")
        self.assertEqual(ListenerUpdate(password="abc").password, "abc")

    def test_proxy_password_shorter_than_three_is_rejected(self):
        with self.assertRaises(ValidationError):
            ListenerInput(port=3128, username="client", password="ab")
        with self.assertRaises(ValidationError):
            ListenerUpdate(password="ab")

    def test_authority_parsing(self):
        self.assertEqual(_parse_authority("example.com:443"), ("example.com", 443))
        self.assertEqual(
            _parse_authority("[2001:4860:4860::8888]:443"),
            ("2001:4860:4860::8888", 443),
        )
        with self.assertRaises(ProxyRequestError):
            _parse_authority("127.0.0.1")


class ProxySecurityTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.encoded = password_hash("proxy-password-123")
        cls.auth = base64.b64encode(b"client:proxy-password-123").decode()

    async def asyncSetUp(self):
        self.server = await asyncio.start_server(
            listener_callback("client", self.encoded), "127.0.0.1", 0
        )
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()

    async def request(self, wire: bytes) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(wire)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(4096), timeout=3)
        writer.close()
        await writer.wait_closed()
        return response

    async def test_missing_credentials_get_407(self):
        response = await self.request(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        self.assertIn(b"407 Proxy Authentication Required", response)
        self.assertIn(b"Proxy-Authenticate: Basic", response)

    async def test_authenticated_private_destination_is_blocked(self):
        wire = (
            f"CONNECT 127.0.0.1:9 HTTP/1.1\r\n"
            f"Proxy-Authorization: Basic {self.auth}\r\n\r\n"
        ).encode()
        response = await self.request(wire)
        self.assertIn(b"403 Forbidden", response)
        self.assertIn(b"non-public destinations are blocked", response)

    async def test_authenticated_http_private_destination_is_blocked(self):
        wire = (
            f"GET http://127.0.0.1:80/ HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\nProxy-Authorization: Basic {self.auth}\r\n\r\n"
        ).encode()
        response = await self.request(wire)
        self.assertIn(b"403 Forbidden", response)

    async def test_plain_http_proxy_forwards_absolute_form_request(self):
        request_lines = []

        async def origin(reader, writer):
            request_lines.append((await reader.readline()).decode().strip())
            headers = []
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                headers.append(line)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        origin_server = await asyncio.start_server(origin, "127.0.0.1", 0)
        origin_port = origin_server.sockets[0].getsockname()[1]

        async def test_resolver(_host, _port):
            return "127.0.0.1", origin_port, socket.AF_INET

        wire = (
            f"GET http://example.test:{origin_port}/path?q=1 HTTP/1.1\r\n"
            f"Host: example.test:{origin_port}\r\n"
            f"Proxy-Authorization: Basic {self.auth}\r\n\r\n"
        ).encode()
        try:
            with patch("app.proxy._resolve_public", new=test_resolver):
                response = await self.request(wire)
        finally:
            origin_server.close()
            await origin_server.wait_closed()
        self.assertIn(b"HTTP/1.1 200 OK", response)
        self.assertTrue(response.endswith(b"OK"))
        self.assertEqual(request_lines, ["GET /path?q=1 HTTP/1.1"])
        self.assertNotIn(self.auth.encode(), response)

    async def test_https_connect_tunnel_works_over_plain_http_proxy(self):
        async def echo(reader, writer):
            try:
                data = await reader.readexactly(4)
                writer.write(data)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        echo_server = await asyncio.start_server(echo, "127.0.0.1", 0)
        echo_port = echo_server.sockets[0].getsockname()[1]

        async def test_resolver(_host, _port):
            return "127.0.0.1", echo_port, socket.AF_INET

        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        wire = (
            f"CONNECT example.test:443 HTTP/1.1\r\n"
            f"Host: example.test:443\r\nProxy-Authorization: Basic {self.auth}\r\n\r\n"
        ).encode()
        try:
            with patch("app.proxy._resolve_public", new=test_resolver):
                writer.write(wire)
                await writer.drain()
                response = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3)
                self.assertIn(b"200 Connection Established", response)
                writer.write(b"PING")
                await writer.drain()
                self.assertEqual(await asyncio.wait_for(reader.readexactly(4), timeout=3), b"PING")
        finally:
            writer.close()
            await writer.wait_closed()
            echo_server.close()
            await echo_server.wait_closed()


if __name__ == "__main__":
    unittest.main()
