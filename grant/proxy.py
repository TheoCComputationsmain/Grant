"""grantctl proxy — local interception daemon for computer-use and local agents."""
from __future__ import annotations

import json
import time
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib import error, request

from . import Grant

HOP = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "accept-encoding",
    "x-grant-request-id",
    "x-grant-receipt",
}


@dataclass
class ProxyState:
    client: Grant
    grant_url: str
    token: str
    open_browser: bool
    poll_interval: float
    max_wait: float


def _send(
    url: str,
    method: str,
    body: bytes | None,
    headers: dict[str, str],
    timeout: float,
) -> tuple[int, dict[str, str], bytes]:
    req = request.Request(url, data=body, method=method, headers=headers)
    try:
        with request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            return response.status, dict(response.headers), raw
    except error.HTTPError as exc:
        raw = exc.read()
        return exc.code, dict(exc.headers), raw


def _json(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None


def make_handler(state: ProxyState):
    class GrantProxyHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            # Never print request lines: query strings may carry credentials.
            print("grantctl proxy: handled request")

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

        def do_PUT(self):
            self._handle()

        def do_PATCH(self):
            self._handle()

        def do_DELETE(self):
            self._handle()

        def do_OPTIONS(self):
            self._handle()

        def do_HEAD(self):
            self._handle()

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
            raw_path = self.path
            path, _, query = raw_path.partition("?")
            target = f"{state.grant_url}/g/http/{state.token}/{path.lstrip('/')}"
            if query:
                target += "?" + query
            headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}

            status, response_headers, raw = _send(target, self.command, body, headers, state.client.timeout)
            payload = _json(raw)
            if status == 202 and isinstance(payload, dict) and payload.get("grant_id"):
                approval_url = str(payload.get("approval_url") or "")
                if state.open_browser and approval_url.startswith(("http://", "https://")):
                    webbrowser.open(approval_url)
                grant_id = str(payload["grant_id"])
                deadline = time.monotonic() + state.max_wait
                while time.monotonic() < deadline:
                    time.sleep(state.poll_interval)
                    status_row = state.client.request_status(grant_id)
                    if status_row.status == "pending":
                        continue
                    if status_row.decision == "reject":
                        raw = json.dumps({"detail": "The human rejected this action."}).encode()
                        status = 403
                        response_headers = {"content-type": "application/json"}
                        break
                    retry_headers = dict(headers)
                    retry_headers["X-Grant-Request-Id"] = grant_id
                    signature = ""
                    if status_row.permission is not None:
                        signature = status_row.permission.signature
                    if signature:
                        retry_headers["X-Grant-Receipt"] = signature
                    status, response_headers, raw = _send(
                        target, self.command, body, retry_headers, state.client.timeout
                    )
                    break

            clean_headers = {k: v for k, v in response_headers.items() if k.lower() not in HOP}
            self.send_response(status)
            for key, value in clean_headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(raw)

    return GrantProxyHandler


def split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def run_proxy(args) -> int:
    client = Grant(args.url, timeout=args.timeout)
    gateway = client.gateway(
        name=args.name,
        upstream_url=args.upstream,
        workspace=args.workspace,
        sensitive_tools=split_csv(args.tools),
        sensitive_paths=split_csv(args.paths),
        sensitive_methods=split_csv(args.methods) or None,
        body_keys=split_csv(args.body_keys),
        default_action=args.default_action,
        ttl_minutes=args.ttl,
    )
    state = ProxyState(
        client=client,
        grant_url=args.url.rstrip("/"),
        token=gateway.token,
        open_browser=args.open,
        poll_interval=max(0.2, args.poll_interval),
        max_wait=max(0, args.max_wait),
    )
    server = ThreadingHTTPServer((args.host, args.port), make_handler(state))
    print(f"Grant local proxy: http://{args.host}:{args.port}/")
    print(f"Grant gateway:     {gateway.http_url}")
    print(f"Grant MCP URL:     {gateway.mcp_url}")
    print("Point your agent or tool client at the local proxy. Sensitive calls will pause for approval.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
