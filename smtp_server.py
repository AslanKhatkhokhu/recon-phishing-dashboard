"""
Local SMTP Relay — RedBalance Red Team Platform
Accepts outbound email from the dashboard and delivers directly to recipient MX servers.
No external SMTP provider needed.

Usage:
    Starts automatically with app.py, or standalone:
        python smtp_server.py --port 2525 --domain example.com
"""

import asyncio
import dns.resolver
import logging
import smtplib
import socket
import ssl
import threading
from email import message_from_bytes
from email.utils import parseaddr

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword, SMTP

log = logging.getLogger("smtp_relay")
log.setLevel(logging.INFO)
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter("[SMTP] %(message)s"))
    log.addHandler(_h)

# Delivery log — list of dicts, most recent first
delivery_log: list[dict] = []
MAX_LOG = 500

_domain = "example.com"

# ──────────────────────────────────────────────────────────────────────────────
# MX resolution + direct delivery
# ──────────────────────────────────────────────────────────────────────────────

def _resolve_mx(domain: str) -> list[str]:
    """Return MX hosts for *domain*, sorted by priority."""
    try:
        answers = dns.resolver.resolve(domain, "MX")
        hosts = sorted(answers, key=lambda r: r.preference)
        return [str(r.exchange).rstrip(".") for r in hosts]
    except Exception as exc:
        log.warning("MX lookup failed for %s: %s", domain, exc)
        return [domain]  # fall back to A record


class IPv4SMTP(smtplib.SMTP):
    """SMTP subclass that forces IPv4 connections."""
    def _get_socket(self, host, port, timeout):
        return socket.create_connection((host, port), timeout,
                                        source_address=self.source_address)


def deliver_to_mx(envelope_from: str, envelope_to: str, raw_message: bytes) -> dict:
    """
    Deliver a single message directly to the recipient's MX server.
    Returns {"ok": True/False, "detail": "..."}.
    """
    _, to_addr = parseaddr(envelope_to)
    if "@" not in to_addr:
        return {"ok": False, "detail": f"Invalid recipient: {envelope_to}"}

    rcpt_domain = to_addr.split("@")[1]
    mx_hosts = _resolve_mx(rcpt_domain)

    last_error = ""
    for mx in mx_hosts:
        try:
            # Resolve to IPv4 explicitly
            ipv4 = socket.getaddrinfo(mx, 25, socket.AF_INET)[0][4][0]
            log.info("Delivering to %s via MX %s (%s)", to_addr, mx, ipv4)
            with smtplib.SMTP(ipv4, 25, timeout=30, local_hostname=_domain) as srv:
                srv.ehlo(_domain)
                # Try STARTTLS if the MX supports it (opportunistic)
                if srv.has_extn("starttls"):
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    srv.starttls(context=ctx)
                    srv.ehlo(_domain)
                srv.sendmail(envelope_from, [to_addr], raw_message)
            log.info("Delivered to %s via %s", to_addr, mx)
            return {"ok": True, "detail": f"Delivered via {mx}"}
        except Exception as exc:
            last_error = f"{mx}: {exc}"
            log.warning("MX %s failed: %s", mx, exc)
            continue

    return {"ok": False, "detail": f"All MX servers failed. Last: {last_error}"}


# ──────────────────────────────────────────────────────────────────────────────
# SMTP handler — receives mail from email_sender.py on localhost
# ──────────────────────────────────────────────────────────────────────────────

class RelayHandler:
    """aiosmtpd handler that relays every accepted message to the recipient MX."""

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(self, server, session, envelope):
        mail_from = envelope.mail_from
        results = []
        for rcpt in envelope.rcpt_tos:
            res = await asyncio.get_event_loop().run_in_executor(
                None, deliver_to_mx, mail_from, rcpt, envelope.content
            )
            results.append({"to": rcpt, **res})
            # Log delivery
            delivery_log.insert(0, {
                "from": mail_from,
                "to": rcpt,
                "ok": res["ok"],
                "detail": res["detail"],
            })
            if len(delivery_log) > MAX_LOG:
                delivery_log.pop()

        failed = [r for r in results if not r["ok"]]
        if failed:
            detail = "; ".join(f"{r['to']}: {r['detail']}" for r in failed)
            log.error("Delivery failed: %s", detail)
            return f"450 Delivery failed: {detail}"

        return "250 Message accepted for delivery"


# ──────────────────────────────────────────────────────────────────────────────
# Server lifecycle
# ──────────────────────────────────────────────────────────────────────────────

_controller: Controller | None = None


def start(port: int = 2525, domain: str = "example.com") -> int:
    """Start the local SMTP relay in a background thread. Returns the port."""
    global _controller, _domain
    _domain = domain

    if _controller is not None:
        log.info("SMTP relay already running on port %d", port)
        return port

    handler = RelayHandler()
    _controller = Controller(
        handler,
        hostname="127.0.0.1",
        port=port,
        ready_timeout=5,
    )
    _controller.start()
    log.info("Local SMTP relay started on 127.0.0.1:%d (HELO %s)", port, domain)
    return port


def stop():
    global _controller
    if _controller:
        _controller.stop()
        _controller = None
        log.info("SMTP relay stopped")


def is_running() -> bool:
    return _controller is not None


def get_log() -> list[dict]:
    return list(delivery_log)


# ──────────────────────────────────────────────────────────────────────────────
# Standalone entry point
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="RedBalance local SMTP relay")
    parser.add_argument("--port", type=int, default=2525)
    parser.add_argument("--domain", default="example.com")
    args = parser.parse_args()

    start(port=args.port, domain=args.domain)
    print(f"SMTP relay running on 127.0.0.1:{args.port} — press Ctrl+C to stop")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        stop()
