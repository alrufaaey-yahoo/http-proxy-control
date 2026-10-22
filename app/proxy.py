from __future__ import annotations

import asyncio
import base64
import ipaddress
import re
import socket
from urllib.parse import urlsplit

from .store import password_matches

MAX_HEADER = 64 * 1024
IDLE_TIMEOUT = 120


class ProxyRequestError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message


def _reply(status: int, reason: str, body: str, headers: bytes = b"") -> bytes:
    payload = body.encode("utf-8")
    return (f"HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(payload)}\r\nConnection: close\r\n".encode() + headers + b"\r\n" + payload)


def _parse_authority(authority: str, default_port: int | None = None) -> tuple[str, int]:
    authority = authority.strip()
    if not authority or "@" in authority:
        raise ProxyRequestError(400, "Invalid destination")
    parsed = urlsplit("//" + authority)
    host = parsed.hostname
    try:
        port = parsed.port or default_port
    except ValueError:
        port = None
    if not host or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or not port or not (1 <= port <= 65535):
        raise ProxyRequestError(400, "Invalid destination")
    return host.rstrip("."), port


async def _resolve_public(host: str, port: int) -> tuple[str, int, int]:
    loop = asyncio.get_running_loop()
    try:
        records = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM), timeout=8
        )
    except (OSError, asyncio.TimeoutError):
        raise ProxyRequestError(502, "Destination could not be resolved")
    seen: set[str] = set()
    public_records: list[tuple[str, int, int]] = []
    for family, _socktype, _proto, _canonname, sockaddr in records:
        ip = sockaddr[0]
        if ip in seen:
            continue
        seen.add(ip)
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        # Fail closed if DNS returns even one private/non-public address.
        if not address.is_global:
            raise ProxyRequestError(403, "Private, local, or non-public destinations are blocked")
        public_records.append((ip, port, family))
    if public_records:
        return public_records[0]
    raise ProxyRequestError(403, "Private, local, or non-public destinations are blocked")


async def _connect(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    ip, port, family = await _resolve_public(host, port)
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(ip, port, family=family), timeout=15
        )
    except (OSError, asyncio.TimeoutError):
        raise ProxyRequestError(502, "Could not connect to destination")


async def _copy_stream(source: asyncio.StreamReader, dest: asyncio.StreamWriter) -> None:
    while True:
        try:
            data = await asyncio.wait_for(source.read(64 * 1024), timeout=IDLE_TIMEOUT)
        except asyncio.TimeoutError:
            break
        if not data:
            break
        dest.write(data)
        await dest.drain()
    try:
        dest.write_eof()
    except (AttributeError, OSError, RuntimeError):
        pass


async def _tunnel(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                  remote_reader: asyncio.StreamReader, remote_writer: asyncio.StreamWriter) -> None:
    tasks = [asyncio.create_task(_copy_stream(client_reader, remote_writer)),
             asyncio.create_task(_copy_stream(remote_reader, client_writer))]
    _done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def _read_chunked(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    total = 0
    while True:
        line = await asyncio.wait_for(reader.readline(), timeout=IDLE_TIMEOUT)
        if not line or len(line) > 8192:
            raise ProxyRequestError(400, "Invalid chunked body")
        writer.write(line)
        await writer.drain()
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            raise ProxyRequestError(400, "Invalid chunked body")
        if size < 0 or total + size > 64 * 1024 * 1024:
            raise ProxyRequestError(413, "Request body too large")
        if size == 0:
            # Forward optional trailers through the terminating blank line.
            while True:
                trailer = await asyncio.wait_for(reader.readline(), timeout=IDLE_TIMEOUT)
                if not trailer or len(trailer) > 8192:
                    raise ProxyRequestError(400, "Invalid chunked trailer")
                writer.write(trailer)
                await writer.drain()
                if trailer in (b"\r\n", b"\n"):
                    return
        data = await asyncio.wait_for(reader.readexactly(size + 2), timeout=IDLE_TIMEOUT)
        if not data.endswith(b"\r\n"):
            raise ProxyRequestError(400, "Invalid chunked body")
        writer.write(data)
        await writer.drain()
        total += size


async def _handle_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                          username: str, stored_hash: str) -> None:
    upstream_writer: asyncio.StreamWriter | None = None
    try:
        try:
            raw_header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
        except asyncio.LimitOverrunError:
            writer.write(_reply(431, "Request Header Fields Too Large", "Request headers too large"))
            await writer.drain()
            return
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            return
        if len(raw_header) > MAX_HEADER:
            writer.write(_reply(431, "Request Header Fields Too Large", "Request headers too large"))
            await writer.drain()
            return
        try:
            lines = raw_header[:-4].decode("latin-1").split("\r\n")
            method, target, version = lines[0].split(" ", 2)
        except (UnicodeDecodeError, ValueError):
            writer.write(_reply(400, "Bad Request", "Malformed request"))
            await writer.drain()
            return
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method) or version not in {"HTTP/1.0", "HTTP/1.1"} or any(char.isspace() for char in target):
            writer.write(_reply(400, "Bad Request", "Invalid request line"))
            await writer.drain()
            return
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if not line or ":" not in line:
                writer.write(_reply(400, "Bad Request", "Malformed header"))
                await writer.drain()
                return
            name, value = line.split(":", 1)
            name, value = name.strip(), value.strip()
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or any((ord(char) < 32 and char != "\t") or ord(char) == 127 for char in value):
                writer.write(_reply(400, "Bad Request", "Invalid header"))
                await writer.drain()
                return
            headers.append((name, value))
        auth_values = [v for k, v in headers if k.lower() == "proxy-authorization"]
        authenticated = False
        if len(auth_values) == 1 and auth_values[0].lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth_values[0][6:].strip(), validate=True).decode("utf-8")
                supplied_user, supplied_password = decoded.split(":", 1)
                authenticated = (supplied_user == username and password_matches(supplied_password, stored_hash))
            except (ValueError, UnicodeDecodeError):
                authenticated = False
        if not authenticated:
            writer.write(_reply(407, "Proxy Authentication Required", "Proxy authentication required",
                                b"Proxy-Authenticate: Basic realm=\"HTTP Proxy\"\r\n"))
            await writer.drain()
            return

        if method.upper() == "CONNECT":
            host, port = _parse_authority(target)
            remote_reader, upstream_writer = await _connect(host, port)
            writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: http-proxy-control\r\n\r\n")
            await writer.drain()
            await _tunnel(reader, writer, remote_reader, upstream_writer)
            return

        parsed = urlsplit(target)
        if parsed.scheme.lower() != "http" or not parsed.hostname or parsed.username or parsed.password:
            raise ProxyRequestError(400, "Use an absolute http:// URL or HTTPS CONNECT")
        host = parsed.hostname
        try:
            port = parsed.port or 80
        except ValueError:
            raise ProxyRequestError(400, "Invalid destination port")
        remote_reader, upstream_writer = await _connect(host, port)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        outgoing = [(k, v) for k, v in headers
                    if k.lower() not in {"proxy-authorization", "proxy-connection", "connection", "keep-alive", "host"}]
        host_header = f"[{host}]" if ":" in host else host
        if port != 80:
            host_header += f":{port}"
        outgoing.append(("Host", host_header))
        outgoing.append(("Connection", "close"))
        request_line = f"{method} {path} {version}\r\n".encode("latin-1", "strict")
        upstream_writer.write(request_line + b"".join(f"{k}: {v}\r\n".encode("latin-1") for k, v in outgoing) + b"\r\n")
        await upstream_writer.drain()
        lengths = [v for k, v in headers if k.lower() == "content-length"]
        transfer = [v.lower() for k, v in headers if k.lower() == "transfer-encoding"]
        if lengths and transfer:
            raise ProxyRequestError(400, "Conflicting request body headers")
        if transfer:
            if len(transfer) != 1 or transfer[0] != "chunked":
                raise ProxyRequestError(501, "Unsupported transfer encoding")
            await _read_chunked(reader, upstream_writer)
        elif lengths:
            if len(lengths) != 1:
                raise ProxyRequestError(400, "Duplicate content length")
            try:
                length = int(lengths[0])
            except ValueError:
                raise ProxyRequestError(400, "Invalid content length")
            if length < 0 or length > 64 * 1024 * 1024:
                raise ProxyRequestError(413, "Request body too large")
            remaining = length
            while remaining:
                data = await asyncio.wait_for(reader.readexactly(min(64 * 1024, remaining)), timeout=IDLE_TIMEOUT)
                upstream_writer.write(data)
                await upstream_writer.drain()
                remaining -= len(data)
        while True:
            try:
                data = await asyncio.wait_for(remote_reader.read(64 * 1024), timeout=IDLE_TIMEOUT)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except ProxyRequestError as exc:
        try:
            reasons = {400: "Bad Request", 403: "Forbidden", 413: "Payload Too Large", 501: "Not Implemented", 502: "Bad Gateway"}
            writer.write(_reply(exc.status, reasons.get(exc.status, "Error"), exc.message))
            await writer.drain()
        except (ConnectionError, OSError):
            pass
    except (ConnectionError, OSError, asyncio.IncompleteReadError, asyncio.TimeoutError, UnicodeError):
        pass
    finally:
        if upstream_writer is not None:
            upstream_writer.close()
            try:
                await upstream_writer.wait_closed()
            except (ConnectionError, OSError):
                pass
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


def listener_callback(username: str, stored_hash: str):
    async def callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        await _handle_request(reader, writer, username, stored_hash)
    return callback
