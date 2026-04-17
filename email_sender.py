"""
Email Sender — RedBalance Red Team Platform
Sends phishing simulation emails via SMTP for authorized engagements.
"""

import smtplib
import ssl
import os
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid


# In-memory SMTP config — overridden by env vars if set
_smtp_config: dict = {
    "host":     os.environ.get("SMTP_HOST",  ""),
    "port":     int(os.environ.get("SMTP_PORT", "587")),
    "user":     os.environ.get("SMTP_USER",  ""),
    "password": os.environ.get("SMTP_PASS",  ""),
    "use_tls":  os.environ.get("SMTP_TLS",   "false").lower() == "true",
}

# Allowed recipient domains whitelist — empty means unrestricted
_allowed_domains: list[str] = []


def get_config() -> dict:
    cfg = {k: v for k, v in _smtp_config.items() if k != "password"}
    cfg["allowed_domains"] = list(_allowed_domains)
    return cfg


def save_config(cfg: dict):
    for key in ("host", "port", "user", "password", "use_tls"):
        if key in cfg:
            if key == "port":
                _smtp_config["port"] = int(cfg["port"])
            elif key == "use_tls":
                _smtp_config["use_tls"] = bool(cfg["use_tls"])
            else:
                _smtp_config[key] = str(cfg[key])
    if "allowed_domains" in cfg:
        _allowed_domains.clear()
        for d in (cfg["allowed_domains"] or []):
            d = d.strip().lstrip("@").lower()
            if d:
                _allowed_domains.append(d)


def is_recipient_allowed(to: str) -> tuple[bool, str]:
    """Check if the recipient email is in the allowed domains list."""
    if not _allowed_domains:
        return True, ""
    domain = to.split("@")[-1].lower() if "@" in to else ""
    if domain in _allowed_domains:
        return True, ""
    return False, f"Recipient domain @{domain} is not in the allowed list: {', '.join('@'+d for d in _allowed_domains)}"


def send_email(
    to: str,
    subject: str,
    body_html: str,
    body_text: str,
    from_addr: str = "",
    reply_to: str = "",
) -> dict:
    """
    Send an email via the configured SMTP server.
    Returns {"ok": True} or {"ok": False, "error": "..."}.
    """
    cfg = _smtp_config
    if not cfg["host"]:
        return {"ok": False, "error": "SMTP host not configured"}
    if not to:
        return {"ok": False, "error": "No recipient (To) specified"}

    allowed, reason = is_recipient_allowed(to)
    if not allowed:
        return {"ok": False, "error": f"Blocked: {reason}"}

    # Aruba requires both envelope and header From = authenticated user.
    # Preserve the desired sender identity as a display name.
    is_aruba = "aruba" in cfg["host"].lower()
    if is_aruba:
        envelope_sender = cfg["user"]
        # Use display name to show the spoofed identity, e.g.
        # "IT Helpdesk <admin@example.com>" while actual addr stays valid
        if from_addr and from_addr != cfg["user"]:
            # Extract a display name from the desired from address
            _name = from_addr.split("@")[0].replace(".", " ").replace("-", " ").title()
            display_from = f"{_name} <{cfg['user']}>"
        else:
            display_from = cfg["user"]
    else:
        envelope_sender = from_addr or cfg["user"]
        display_from = from_addr or cfg["user"]

    # Derive domain for Message-ID from sender address
    _msg_domain = display_from.split("@")[1] if "@" in display_from else "example.com"

    msg = MIMEMultipart("alternative")
    msg["Subject"]    = subject
    msg["From"]       = display_from
    msg["To"]         = to
    msg["Date"]       = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=_msg_domain)
    if reply_to:
        msg["Reply-To"] = reply_to

    msg.attach(MIMEText(body_text, "plain", "utf-8"))
    msg.attach(MIMEText(body_html, "html",  "utf-8"))

    is_local = cfg["host"] in ("127.0.0.1", "localhost") and cfg["password"] == "local"

    try:
        if is_local:
            # Local SMTP relay — no auth, no TLS
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as server:
                server.ehlo()
                server.sendmail(envelope_sender, [to], msg.as_string())
        elif cfg["use_tls"]:
            context = ssl.create_default_context()
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as server:
                server.ehlo()
                server.starttls(context=context)
                server.login(cfg["user"], cfg["password"])
                server.sendmail(envelope_sender, [to], msg.as_string())
        else:
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=15) as server:
                server.login(cfg["user"], cfg["password"])
                server.sendmail(envelope_sender, [to], msg.as_string())

        return {"ok": True, "from": display_from, "to": to, "subject": subject}

    except smtplib.SMTPAuthenticationError:
        return {"ok": False, "error": "SMTP authentication failed — check username/password"}
    except smtplib.SMTPRecipientsRefused:
        return {"ok": False, "error": f"Recipient refused by server: {to}"}
    except smtplib.SMTPException as e:
        return {"ok": False, "error": f"SMTP error: {e}"}
    except OSError as e:
        return {"ok": False, "error": f"Connection error: {e}"}
