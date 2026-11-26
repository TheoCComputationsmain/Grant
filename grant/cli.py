"""grantctl — a tiny command line client for Grant."""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from typing import Any, Sequence

from . import DEFAULT_BASE_URL, Grant
from .proxy import run_proxy, split_csv


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--url", default=DEFAULT_BASE_URL, help="Grant service base URL")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")


def _print(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="grantctl", description="Grant consent control")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="check a Grant service")
    _common(doctor)

    req = sub.add_parser("request", help="create an approval request")
    _common(req)
    req.add_argument("--agent", required=True)
    req.add_argument("--action", required=True)
    req.add_argument("--summary", required=True)
    req.add_argument("--scope", default="{}", help="JSON object describing exact scope")
    req.add_argument("--workspace", default="public")
    req.add_argument("--requester", default="agent")
    req.add_argument("--ttl", type=int, default=30, dest="ttl_minutes")

    status = sub.add_parser("status", help="read request status")
    _common(status)
    status.add_argument("request_id")

    perms = sub.add_parser("permissions", help="list active permissions for an agent")
    _common(perms)
    perms.add_argument("agent")

    verify = sub.add_parser("verify", help="verify a signed permission")
    _common(verify)
    verify.add_argument("permission_id")
    verify.add_argument("signature")

    gateway = sub.add_parser("gateway", help="register a zero-code tool gateway")
    _common(gateway)
    gateway.add_argument("--name", required=True)
    gateway.add_argument("--upstream", required=True, help="upstream MCP/API URL")
    gateway.add_argument("--workspace", default="public")
    gateway.add_argument("--tools", default="", help="comma-separated sensitive MCP tool names")
    gateway.add_argument("--paths", default="", help="comma-separated sensitive HTTP path parts")
    gateway.add_argument("--methods", default="", help="comma-separated methods, default POST,PUT,PATCH,DELETE")
    gateway.add_argument("--body-keys", default="", help="comma-separated payload keys that trigger review")
    gateway.add_argument("--default-action", choices=["allow", "review"], default="review")
    gateway.add_argument("--ttl", type=int, default=15, dest="ttl_minutes")

    proxy = sub.add_parser("proxy", help="run a local interception daemon")
    _common(proxy)
    proxy.add_argument("--name", default="Local tool proxy")
    proxy.add_argument("--upstream", required=True, help="upstream URL to protect")
    proxy.add_argument("--host", default="127.0.0.1")
    proxy.add_argument("--port", type=int, default=8787)
    proxy.add_argument("--workspace", default="public")
    proxy.add_argument("--tools", default="")
    proxy.add_argument("--paths", default="")
    proxy.add_argument("--methods", default="")
    proxy.add_argument("--body-keys", default="")
    proxy.add_argument("--default-action", choices=["allow", "review"], default="review")
    proxy.add_argument("--ttl", type=int, default=15, dest="ttl_minutes")
    proxy.add_argument("--open", action="store_true", help="open each approval link in a browser")
    proxy.add_argument("--poll-interval", type=float, default=1.0)
    proxy.add_argument("--max-wait", type=float, default=300.0)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    client = Grant(args.url, timeout=args.timeout)

    if args.command == "doctor":
        _print(client._call("GET", "/health/ready"))
    elif args.command == "request":
        try:
            scope = json.loads(args.scope)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"--scope must be valid JSON: {exc}") from exc
        if not isinstance(scope, dict):
            raise SystemExit("--scope must be a JSON object")
        approval = client.request(
            agent=args.agent,
            action=args.action,
            summary=args.summary,
            scope=scope,
            workspace=args.workspace,
            requester=args.requester,
            ttl_minutes=args.ttl_minutes,
        )
        _print(asdict(approval))
    elif args.command == "status":
        _print(asdict(client.status(args.request_id)))
    elif args.command == "permissions":
        _print([asdict(item) for item in client.permissions(args.agent)])
    elif args.command == "verify":
        _print(client.verify(args.permission_id, args.signature))
    elif args.command == "gateway":
        result = client.gateway(
            name=args.name,
            upstream_url=args.upstream,
            workspace=args.workspace,
            sensitive_tools=split_csv(args.tools),
            sensitive_paths=split_csv(args.paths),
            sensitive_methods=split_csv(args.methods) or None,
            body_keys=split_csv(args.body_keys),
            default_action=args.default_action,
            ttl_minutes=args.ttl_minutes,
        )
        _print(
            {
                "id": result.id,
                "token": result.token,
                "http_url": result.http_url,
                "mcp_url": result.mcp_url,
                "policy": result.policy,
                "note": "Store the token privately. Anyone with these URLs can use the gateway.",
            }
        )
    elif args.command == "proxy":
        return run_proxy(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
