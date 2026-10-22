import asyncio
import base64
import unittest

from app.proxy import ProxyRequestError, _parse_authority, listener_callback
from app.store import password_hash, password_matches


class PasswordTests(unittest.TestCase):
    def test_password_hash_verifies(self):
        encoded = password_hash("correct horse battery staple")
        self.assertTrue(password_matches("correct horse battery staple", encoded))
        self.assertFalse(password_matches("wrong password", encoded))

    def test_authority_parsing(self):
        self.assertEqual(_parse_authority("example.com:443"), ("example.com", 443))
        self.assertEqual(_parse_authority("[2001:4860:4860::8888]:443"), ("2001:4860:4860::8888", 443))
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
        response = await self.request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")
        self.assertIn(b"407 Proxy Authentication Required", response)
        self.assertIn(b"Proxy-Authenticate: Basic", response)

    async def test_authenticated_private_destination_is_blocked(self):
        wire = (f"CONNECT 127.0.0.1:9 HTTP/1.1\r\nProxy-Authorization: Basic {self.auth}\r\n\r\n").encode()
        response = await self.request(wire)
        self.assertIn(b"403 Forbidden", response)
        self.assertIn(b"non-public destinations are blocked", response)

    async def test_authenticated_http_private_destination_is_blocked(self):
        wire = (f"GET http://127.0.0.1:80/ HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: Basic {self.auth}\r\n\r\n").encode()
        response = await self.request(wire)
        self.assertIn(b"403 Forbidden", response)


if __name__ == "__main__":
    unittest.main()
