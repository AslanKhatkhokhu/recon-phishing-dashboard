"""
GoPhish API Bridge — RedBalance
Proxies requests between the Flask dashboard and the GoPhish admin API.
GoPhish admin runs at https://127.0.0.1:3333 (TLS, self-signed cert).
"""

import os
import json
import sqlite3
import urllib.request
import urllib.error
import ssl

# Path to gophish.db — sits next to osint_dashboard/ in the project root
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_GOPHISH_DB = os.path.join(_THIS_DIR, "..", "gophish", "gophish.db")


def _auto_read_key() -> str:
    """Try to read the API key from gophish.db automatically."""
    env_key = os.environ.get("GOPHISH_API_KEY", "")
    if env_key:
        return env_key
    db_path = os.path.abspath(_GOPHISH_DB)
    try:
        if not os.path.isfile(db_path):
            return ""
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT api_key FROM users WHERE username='admin' LIMIT 1"
        ).fetchone()
        conn.close()
        if row:
            return row[0]
    except Exception as e:
        print(f"[gophish_api] auto-key failed: {e}")
    return ""


GOPHISH_URL  = os.environ.get("GOPHISH_URL",      "https://127.0.0.1:3333")
GOPHISH_KEY  = _auto_read_key()
PHISH_SERVER = os.environ.get("GOPHISH_PHISH_URL", "http://127.0.0.1:8080")

# Accept GoPhish's self-signed certificate
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode    = ssl.CERT_NONE


def _key() -> str:
    """Return API key, falling back to env var."""
    return GOPHISH_KEY


def _req(method: str, path: str, body: dict = None) -> dict | list:
    url = f"{GOPHISH_URL}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req  = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Authorization": f"Bearer {_key()}",
            "Content-Type":  "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": e.reason, "status": e.code, "body": e.read().decode()}
    except Exception as e:
        return {"error": str(e)}


# ── Connectivity ──────────────────────────────────────────────────────────────

def ping() -> dict:
    """Returns {"ok": True} if GoPhish is reachable and key is valid."""
    if not _key():
        return {"ok": False, "error": "GOPHISH_API_KEY not set"}
    result = _req("GET", "/api/campaigns/")
    if isinstance(result, list):
        return {"ok": True, "phish_url": PHISH_SERVER}
    return {"ok": False, "error": result.get("error", "unknown")}


def set_key(api_key: str):
    global GOPHISH_KEY
    GOPHISH_KEY = api_key


# ── Landing Pages ─────────────────────────────────────────────────────────────

def list_pages() -> list:
    return _req("GET", "/api/pages/")


def get_page(page_id: int) -> dict:
    return _req("GET", f"/api/pages/{page_id}")


def create_page(name: str, html: str, capture_credentials=True,
                capture_passwords=True, redirect_url: str = "") -> dict:
    return _req("POST", "/api/pages/", {
        "name":                name,
        "html":                html,
        "capture_credentials": capture_credentials,
        "capture_passwords":   capture_passwords,
        "redirect_url":        redirect_url,
    })


def update_page(page_id: int, name: str, html: str, capture_credentials=True,
                capture_passwords=True, redirect_url: str = "") -> dict:
    return _req("PUT", f"/api/pages/{page_id}", {
        "name":                name,
        "html":                html,
        "capture_credentials": capture_credentials,
        "capture_passwords":   capture_passwords,
        "redirect_url":        redirect_url,
    })


def delete_page(page_id: int) -> dict:
    return _req("DELETE", f"/api/pages/{page_id}")


# ── Email Templates ───────────────────────────────────────────────────────────

def list_templates() -> list:
    return _req("GET", "/api/templates/")


def create_template(name: str, subject: str, html: str, text: str = "",
                    envelope_sender: str = "") -> dict:
    return _req("POST", "/api/templates/", {
        "name":            name,
        "subject":         subject,
        "html":            html,
        "text":            text,
        "envelope_sender": envelope_sender,
        "attachments":     [],
    })


def update_template(tpl_id: int, name: str, subject: str, html: str,
                    text: str = "", envelope_sender: str = "") -> dict:
    return _req("PUT", f"/api/templates/{tpl_id}", {
        "name":            name,
        "subject":         subject,
        "html":            html,
        "text":            text,
        "envelope_sender": envelope_sender,
        "attachments":     [],
    })


def delete_template(tpl_id: int) -> dict:
    return _req("DELETE", f"/api/templates/{tpl_id}")


# ── Sending Profiles ──────────────────────────────────────────────────────────

def list_smtp() -> list:
    return _req("GET", "/api/smtp/")


def create_smtp(name: str, host: str, port: int, username: str, password: str,
                from_address: str = "", use_tls: bool = True) -> dict:
    return _req("POST", "/api/smtp/", {
        "name":         name,
        "host":         f"{host}:{port}",
        "username":     username,
        "password":     password,
        "from_address": from_address or username,
        "interface_type": "SMTP",
        "ignore_cert_errors": False,
        "headers": [],
    })


def delete_smtp(smtp_id: int) -> dict:
    return _req("DELETE", f"/api/smtp/{smtp_id}")


# ── Target Groups ─────────────────────────────────────────────────────────────

def list_groups() -> list:
    return _req("GET", "/api/groups/")


def create_group(name: str, targets: list[dict]) -> dict:
    """targets = [{"first_name":"","last_name":"","email":"","position":""}]"""
    return _req("POST", "/api/groups/", {"name": name, "targets": targets})


def update_group(group_id: int, name: str, targets: list[dict]) -> dict:
    return _req("PUT", f"/api/groups/{group_id}", {"name": name, "targets": targets})


def delete_group(group_id: int) -> dict:
    return _req("DELETE", f"/api/groups/{group_id}")


# ── Campaigns ─────────────────────────────────────────────────────────────────

def list_campaigns() -> list:
    return _req("GET", "/api/campaigns/")


def create_campaign(name: str, template_name: str = "", page_name: str = "",
                    smtp_name: str = "", group_name: str = "",
                    template_id: int = 0, page_id: int = 0,
                    smtp_id: int = 0, group_id: int = 0,
                    url: str = "", launch_date: str = "") -> dict:
    """Create a campaign. Prefer name-based refs (more reliable) over IDs."""
    from datetime import datetime, timezone
    payload = {
        "name":        name,
        "template":    {"name": template_name} if template_name else {"id": template_id},
        "page":        {"name": page_name}     if page_name     else {"id": page_id},
        "smtp":        {"name": smtp_name}     if smtp_name     else {"id": smtp_id},
        "groups":      [{"name": group_name}   if group_name    else {"id": group_id}],
        "url":         url or PHISH_SERVER,
        "launch_date": launch_date or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
    }
    return _req("POST", "/api/campaigns/", payload)


def get_campaign(campaign_id: int) -> dict:
    return _req("GET", f"/api/campaigns/{campaign_id}")


def get_campaign_results(campaign_id: int) -> dict:
    return _req("GET", f"/api/campaigns/{campaign_id}/results")


def delete_campaign(campaign_id: int) -> dict:
    return _req("DELETE", f"/api/campaigns/{campaign_id}")


def complete_campaign(campaign_id: int) -> dict:
    return _req("GET", f"/api/campaigns/{campaign_id}/complete")
