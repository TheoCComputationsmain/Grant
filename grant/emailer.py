"""Tiny magic-link email delivery for Grant.

No third-party SDKs. AgentMail and Resend use their HTTPS APIs, SMTP uses the
standard library, and development falls back to printing the link to the
console. No magic link token or provider credential is ever written to
application logs.
"""
from __future__ import annotations

import json
import os
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any, Mapping
from urllib import error, request
from urllib.parse import quote

AGENTMAIL_URL = "https://api.agentmail.to/v0"
AGENTMAIL_INBOX_CLIENT_ID = "grant-auth-mail-v1"
RESEND_URL = "https://api.resend.com/emails"
_AGENTMAIL_INBOX = ""


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
    if explicit in {"agentmail", "resend", "smtp", "console"}:
        return explicit
    if env.get("RESEND_API_KEY", "").strip():
        return "resend"
    if env.get("SMTP_HOST", "").strip():
        return "smtp"
    if env.get("AGENTMAIL_API_KEY", "").strip():
        return "agentmail"
    return "console" if not production else ""


def _agentmail_request(
    api_key: str, method: str, path: str, payload: Mapping[str, Any] | None = None
) -> Mapping[str, Any]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = request.Request(
        f"{AGENTMAIL_URL}{path}",
        data=data,
        method=method,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    try:
        with request.urlopen(req, timeout=10) as response:
            raw = response.read().decode("utf-8")
            if response.status >= 300:
                raise EmailError(f"AgentMail returned {response.status}.")
            return json.loads(raw or "{}")
    except error.HTTPError as exc:
        raise EmailError(f"AgentMail returned {exc.code}.") from None
    except error.URLError as exc:
        raise EmailError("AgentMail is unreachable.") from exc
    except ValueError:
        raise EmailError("AgentMail returned invalid JSON.") from None


def _agentmail_inbox(env: Mapping[str, str], api_key: str) -> str:
    global _AGENTMAIL_INBOX
    configured = str(
        env.get("GRANT_AGENTMAIL_INBOX")
        or env.get("AGENTMAIL_INBOX")
        or env.get("AGENTMAIL_INBOX_ID")
        or ""
    ).strip()
    if configured:
        return configured
    if _AGENTMAIL_INBOX:
        return _AGENTMAIL_INBOX
    created = _agentmail_request(
        api_key,
        "POST",
        "/inboxes",
        {"client_id": AGENTMAIL_INBOX_CLIENT_ID},
    )
    inbox = str(created.get("inbox_id") or created.get("email") or "").strip()
    if not inbox:
        raise EmailError("AgentMail did not return an inbox.")
    _AGENTMAIL_INBOX = inbox
    return inbox


def _send_agentmail_message(
    env: Mapping[str, str], to: str, subject: str, text: str
) -> None:
    api_key = str(env.get("AGENTMAIL_API_KEY", "")).strip()
    if not api_key:
        raise EmailError("AGENTMAIL_API_KEY is not configured.")
    inbox = _agentmail_inbox(env, api_key)
    _agentmail_request(
        api_key,
        "POST",
        f"/inboxes/{quote(inbox, safe='')}/messages/send",
        {"to": to, "subject": subject, "text": text},
    )


def _send_resend_message(
    env: Mapping[str, str], to: str, subject: str, text: str
) -> None:
    api_key = str(env.get("RESEND_API_KEY", "")).strip()
    sender = str(env.get("GRANT_EMAIL_FROM", "Grant <onboarding@resend.dev>")).strip()
    if not api_key:
        raise EmailError("RESEND_API_KEY is not configured.")
    payload = json.dumps(
        {"from": sender, "to": [to], "subject": subject, "text": text}
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


def _send_smtp_message(
    env: Mapping[str, str], to: str, subject: str, text: str
) -> None:
    host = str(env.get("SMTP_HOST", "")).strip()
    port = int(str(env.get("SMTP_PORT", "587")).strip() or 587)
    sender = str(env.get("GRANT_EMAIL_FROM", env.get("SMTP_FROM", ""))).strip()
    if not host or not sender:
        raise EmailError("SMTP_HOST and GRANT_EMAIL_FROM are required.")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = to
    message["Subject"] = subject
    message.set_content(text)
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


def _send_resend(env: Mapping[str, str], to: str, url: str) -> None:
    _send_resend_message(
        env,
        to,
        "Your Grant sign-in link",
        "Open this link to sign in to Grant. It expires soon and can only "
        f"be used once.\n\n{url}\n\nIf you did not request this, ignore it.\n",
    )


def _send_smtp(env: Mapping[str, str], to: str, url: str) -> None:
    _send_smtp_message(
        env,
        to,
        "Your Grant sign-in link",
        "Open this link to sign in to Grant. It expires soon and can only "
        f"be used once.\n\n{url}\n\nIf you did not request this, ignore it.\n",
    )


def _send_agentmail(env: Mapping[str, str], to: str, url: str) -> None:
    _send_agentmail_message(
        env,
        to,
        "Your Grant sign-in link",
        "Open this link to sign in to Grant. It expires soon and can only "
        f"be used once.\n\n{url}\n\nIf you did not request this, ignore it.\n",
    )


def _delivery(env: Mapping[str, str], *, production: bool) -> str:
    return provider_name(env, production=production)


def send_magic_link(to: str, url: str, env: Mapping[str, str] | None = None) -> str:
    """Deliver a one-time sign-in link. Returns the provider name."""
    environ = env if env is not None else os.environ
    production = (
        str(environ.get("GRANT_APP_ENV", "development")).strip().lower() == "production"
        or str(environ.get("VERCEL", "")).strip() == "1"
    )
    provider = _delivery(environ, production=production)
    if provider == "agentmail":
        _send_agentmail(environ, to, url)
        return provider
    if provider == "resend":
        _send_resend(environ, to, url)
        return provider
    if provider == "smtp":
        _send_smtp(environ, to, url)
        return provider
    if provider == "console":
        if production:
            raise EmailError(
                "No email provider configured. Set AGENTMAIL_API_KEY, "
                "RESEND_API_KEY, or SMTP_HOST."
            )
        print(f"[Grant magic link for {mask_email(to)}] {url}")
        return provider
    raise EmailError("No email provider configured.")


def send_otp(to: str, code: str, env: Mapping[str, str] | None = None) -> str:
    """Deliver a one-time numeric sign-in code. Returns the provider name."""
    environ = env if env is not None else os.environ
    production = (
        str(environ.get("GRANT_APP_ENV", "development")).strip().lower() == "production"
        or str(environ.get("VERCEL", "")).strip() == "1"
    )
    provider = _delivery(environ, production=production)
    text = (
        "Your Grant sign-in code is "
        f"{code}. It expires in 10 minutes and works once.\n\n"
        "If you did not request this, ignore this message.\n"
    )
    if provider == "agentmail":
        _send_agentmail_message(environ, to, "Your Grant sign-in code", text)
        return provider
    if provider == "resend":
        _send_resend_message(environ, to, "Your Grant sign-in code", text)
        return provider
    if provider == "smtp":
        _send_smtp_message(environ, to, "Your Grant sign-in code", text)
        return provider
    if provider == "console":
        if production:
            raise EmailError(
                "No email provider configured. Set AGENTMAIL_API_KEY, "
                "RESEND_API_KEY, or SMTP_HOST."
            )
        print(f"[Grant sign-in code for {mask_email(to)}] {code}")
        return provider
    raise EmailError("No email provider configured.")
