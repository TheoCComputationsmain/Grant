"""Tiny magic-link email delivery for Grant.

No third-party SDKs. Resend uses its HTTPS API, SMTP uses the standard library,
and development falls back to printing the link to the console. No magic link
token or provider credential is ever written to application logs.
"""
from __future__ import annotations

import json
import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Mapping
from urllib import error, request

RESEND_URL = "https://api.resend.com/emails"


class EmailError(RuntimeError):
    """The configured mail provider could not deliver a magic link."""


def mask_email(value: str) -> str:
    email = str(value or "")
    if "@" not in email:
        return "a user"
    name, domain = email.split("@", 1)
    head = name[:2] if name else "u"
    return f"{head}***@{domain}"


def provider_name(env: Mapping[str, str], *, production: bool) -> str:
    explicit = str(env.get("GRANT_EMAIL_PROVIDER", "")).strip().lower()
    if explicit in {"resend", "smtp", "console"}:
        return explicit
    if env.get("RESEND_API_KEY", "").strip():
        return "resend"
    if env.get("SMTP_HOST", "").strip():
        return "smtp"
    return "console" if not production else ""


def _send_resend(env: Mapping[str, str], to: str, url: str) -> None:
    api_key = str(env.get("RESEND_API_KEY", "")).strip()
    sender = str(env.get("GRANT_EMAIL_FROM", "Grant <onboarding@resend.dev>")).strip()
    if not api_key:
        raise EmailError("RESEND_API_KEY is not configured.")
    payload = json.dumps(
        {
            "from": sender,
            "to": [to],
            "subject": "Your Grant sign-in link",
            "text": (
                "Open this link to sign in to Grant. It expires soon and can only "
                f"be used once.\n\n{url}\n\nIf you did not request this, ignore it.\n"
            ),
        }
    ).encode("utf-8")
    req = request.Request(
        RESEND_URL,
        data=payload,
        method="POST",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    try:
        with request.urlopen(req, timeout=10) as response:
            if response.status >= 300:
                raise EmailError(f"Resend returned {response.status}.")
    except error.HTTPError as exc:
        raise EmailError(f"Resend returned {exc.code}.") from None
    except error.URLError as exc:
        raise EmailError("Resend is unreachable.") from exc


def _send_smtp(env: Mapping[str, str], to: str, url: str) -> None:
    host = str(env.get("SMTP_HOST", "")).strip()
    port = int(str(env.get("SMTP_PORT", "587")).strip() or 587)
    sender = str(env.get("GRANT_EMAIL_FROM", env.get("SMTP_FROM", ""))).strip()
    if not host or not sender:
        raise EmailError("SMTP_HOST and GRANT_EMAIL_FROM are required.")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = to
    message["Subject"] = "Your Grant sign-in link"
    message.set_content(
        "Open this link to sign in to Grant. It expires soon and can only be "
        f"used once.\n\n{url}\n\nIf you did not request this, ignore it.\n"
    )
    user = str(env.get("SMTP_USER", "")).strip()
    password = str(env.get("SMTP_PASSWORD", "")).strip()
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=10) as smtp:
                if user:
                    smtp.login(user, password)
                smtp.send_message(message)
            return
        with smtplib.SMTP(host, port, timeout=10) as smtp:
            if str(env.get("SMTP_TLS", "1")).strip().lower() in {"1", "true", "yes"}:
                smtp.starttls(context=ssl.create_default_context())
            if user:
                smtp.login(user, password)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise EmailError("SMTP delivery failed.") from exc


def send_magic_link(to: str, url: str, env: Mapping[str, str] | None = None) -> str:
    """Deliver a one-time sign-in link. Returns the provider name."""
    environ = env if env is not None else os.environ
    production = (
        str(environ.get("GRANT_APP_ENV", "development")).strip().lower() == "production"
        or str(environ.get("VERCEL", "")).strip() == "1"
    )
    provider = provider_name(environ, production=production)
    if provider == "resend":
        _send_resend(environ, to, url)
        return provider
    if provider == "smtp":
        _send_smtp(environ, to, url)
        return provider
    if provider == "console":
        if production:
            raise EmailError(
                "No email provider configured. Set RESEND_API_KEY or SMTP_HOST."
            )
        print(f"[Grant magic link for {mask_email(to)}] {url}")
        return provider
    raise EmailError("No email provider configured.")
