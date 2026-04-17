"""
OSINT Dashboard — Flask Backend
Orchestrates OSINT tools, streams live logs via SSE, stores results in memory.
"""

import json
import os
import queue
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid

# Load .env if present (optional convenience — env vars always take precedence)
try:
    from dotenv import load_dotenv
    load_dotenv(override=False)
except ImportError:
    pass

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

from tools import ToolRunner
import phishing as phishing_mod
import email_sender as mailer
import gophish_api as gophish
import profiles as profiles_mod
import vishing as vishing_mod
import voip as voip_mod
import smtp_server as local_smtp
import db as db_mod

app = Flask(__name__)

# Ensure vishing audio output directory exists
os.makedirs(os.path.join(os.path.dirname(__file__), "static", "vishing_audio"), exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), "static", "recordings"), exist_ok=True)

# Initialize database and load persisted API keys
db_mod.init()
_loaded_keys = db_mod.load_api_keys_to_env()
if _loaded_keys:
    print(f"[*] Loaded {_loaded_keys} API key(s) from database")
# In-memory scan storage: { scan_id: { id, status, inputs, results, logs } }
scans: dict = {}
# Per-scan event queues for SSE
scan_queues: dict[str, queue.Queue] = {}
# Per-scan and per-thread cancel events
cancel_events: dict[str, threading.Event] = {}   # key = scan_id or scan_id:thread_id
# In-memory vishing campaigns: { campaign_id: { id, name, script_key, targets, calls, created } }
vishing_campaigns: dict = {}


# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json(force=True)
    scan_id = uuid.uuid4().hex[:10]

    scans[scan_id] = {
        "id": scan_id,
        "status": "running",
        "inputs": data,
        "results": {},
        "logs": [],
        "started_at": time.time(),
    }
    scan_queues[scan_id] = queue.Queue()
    cancel_events[scan_id] = threading.Event()

    thread = threading.Thread(target=_run_scan, args=(scan_id, data), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id})


@app.route("/api/stream/<scan_id>")
def stream(scan_id: str):
    """Server-Sent Events endpoint — streams log/result events to the browser."""
    if scan_id not in scan_queues:
        return Response(
            f"data: {json.dumps({'type': 'error', 'msg': 'Scan not found'})}\n\n",
            mimetype="text/event-stream",
        )

    def generate():
        q = scan_queues[scan_id]
        while True:
            try:
                event = q.get(timeout=45)
                # Persist logs in scan record
                if event.get("type") == "log":
                    scans[scan_id]["logs"].append(event)
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("type") == "done":
                    # Only truly close if no sub-threads are still running
                    threads = scans[scan_id].get("threads", {})
                    if not threads or all(t["status"] == "done" for t in threads.values()):
                        break
                    # Otherwise keep streaming — more events coming from sub-threads
            except queue.Empty:
                # Heartbeat to keep connection alive
                yield f"data: {json.dumps({'type': 'ping'})}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/results/<scan_id>")
def get_results(scan_id: str):
    if scan_id not in scans:
        return jsonify({"error": "not found"}), 404
    return jsonify(scans[scan_id])


@app.route("/api/scans/<scan_id>/manual-intel", methods=["POST"])
def add_manual_intel(scan_id: str):
    """Inject a manually-entered intel item into a scan's results."""
    if scan_id not in scans:
        # Allow adding to a virtual "manual" scan bucket
        scans[scan_id] = {
            "id": scan_id, "status": "done", "inputs": {}, "results": {},
            "logs": [], "started_at": time.time(),
        }
    data   = request.get_json(force=True)
    kind   = data.get("kind", "note")   # note | email | social | person | hash
    value  = data.get("value", "").strip()
    label  = data.get("label", "").strip()
    source = data.get("source", "manual")
    if not value:
        return jsonify({"error": "value required"}), 400

    scan = scans[scan_id]
    manual = scan["results"].setdefault("manual_intel", {"items": []})
    item = {"kind": kind, "value": value, "label": label, "source": source, "added_at": time.time()}
    manual["items"].append(item)

    # Also propagate into web_scrape people list if it's a person entry
    if kind == "person":
        web = scan["results"].setdefault("web_scrape", {"people": [], "emails_found": [], "pages_crawled": []})
        web["people"].append({
            "name":       value,
            "title":      data.get("title", ""),
            "department": data.get("department", ""),
            "email":      data.get("email", ""),
            "source":     "manual",
        })

    return jsonify({"ok": True, "item": item})


# ──────────────────────────────────────────────────────────────────────────────
# Live target injection — add a name/email/username mid-scan → new thread
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/scans/<scan_id>/add-target", methods=["POST"])
def add_target(scan_id: str):
    """
    Add a new target to a running (or finished) scan.
    Spawns a parallel thread that runs the full recon pipeline for the
    new input and merges results back under the same scan_id.

    Body: { "person_name": "...", "username": "...", "email": "...",
            "company": "...", "domain": "..." }
    At least one field required.
    """
    data = request.get_json(force=True)

    if scan_id not in scans:
        return jsonify({"error": "scan not found"}), 404

    # Require at least one input
    if not any(data.get(k, "").strip() for k in
               ("person_name", "username", "email", "company", "domain")):
        return jsonify({"error": "provide at least one target field"}), 400

    # Generate a sub-thread ID
    thread_id = uuid.uuid4().hex[:8]
    thread_key = f"thread_{thread_id}"
    label = data.get("person_name") or data.get("username") or data.get("email") or data.get("company") or data.get("domain")

    scan = scans[scan_id]
    q = scan_queues.get(scan_id)

    # If scan is already done, re-open its queue for events
    if scan["status"] == "done":
        scan["status"] = "running"
        if q is None or q is True:
            scan_queues[scan_id] = queue.Queue()
            q = scan_queues[scan_id]

    # Create cancel event for this thread
    cancel_key = f"{scan_id}:{thread_id}"
    cancel_events[cancel_key] = threading.Event()

    # Track sub-threads
    scan.setdefault("threads", {})[thread_id] = {
        "id": thread_id,
        "inputs": data,
        "label": label,
        "status": "running",
        "started_at": time.time(),
    }

    def _run_sub_thread():
        sub_q = scan_queues[scan_id]
        sub_ce = cancel_events[cancel_key]
        runner = ToolRunner(scan_id, sub_q, cancel_event=sub_ce)
        sub_q.put({"type": "phase", "msg": f"[Thread {thread_id}] New target: {label}"})

        def _stop():
            return runner.cancelled

        sub_results = {}

        pn = data.get("person_name", "").strip()
        un = data.get("username", "").strip()
        em = data.get("email", "").strip()
        co = data.get("company", "").strip()
        dm = data.get("domain", "").strip().lstrip("@")

        try:
            if un and not _stop():
                sub_q.put({"type": "phase", "msg": f"[{thread_id}] Username recon — {un}"})
                if not _stop(): sub_results["sherlock"]    = runner.run_sherlock(un)
                if not _stop(): sub_results["whatsmyname"] = runner.run_whatsmyname(un)
                if not _stop(): sub_results["gitfive"]     = runner.run_gitfive(un)

            if em and not _stop():
                sub_q.put({"type": "phase", "msg": f"[{thread_id}] Email recon — {em}"})
                if not _stop(): sub_results["holehe"] = runner.run_holehe(em)
                if not _stop(): sub_results["hibp"]   = runner.run_haveibeenpwned(em)
                if not _stop(): sub_results["emailrep"] = runner.run_emailrep(em)

            if dm and not _stop():
                sub_q.put({"type": "phase", "msg": f"[{thread_id}] Domain recon — {dm}"})
                if not _stop(): sub_results["theharvester"] = runner.run_theharvester(dm)
                if not _stop(): sub_results["subfinder"]    = runner.run_subfinder(dm)
                if not _stop():
                    sub_q.put({"type": "phase", "msg": f"[{thread_id}] Website scrape — https://{dm}"})
                    sub_results["web_scrape"] = runner.run_web_scrape(f"https://{dm}")

            if pn and not _stop():
                sub_q.put({"type": "phase", "msg": f"[{thread_id}] Person name recon — {pn}"})
                if not _stop(): sub_results["maigret"]            = runner.run_maigret(pn)
                if not _stop(): sub_results["social_analyzer"]    = runner.run_social_analyzer(pn)
                if not _stop(): sub_results["google_dork_person"] = runner.run_google_dork(pn, query_type="person")

            if co and not _stop():
                sub_q.put({"type": "phase", "msg": f"[{thread_id}] Company recon — {co}"})
                if not _stop(): sub_results["company_search"]     = runner.run_company_search(co)
                if not _stop(): sub_results["google_dork_company"] = runner.run_google_dork(co, query_type="company")

            gh_query = co or pn
            if gh_query and not _stop():
                sub_q.put({"type": "phase", "msg": f"[{thread_id}] GitHub search — {gh_query}"})
                sub_results["github"] = runner.run_github_dork(gh_query)

        except Exception as exc:
            sub_q.put({"type": "error", "tool": f"thread_{thread_id}", "msg": str(exc)})

        # Merge results into main scan under thread_key
        scan["results"][thread_key] = {
            "label": label,
            "inputs": data,
            "results": sub_results,
        }
        scan["threads"][thread_id]["status"] = "stopped" if _stop() else "done"
        scan["threads"][thread_id]["ended_at"] = time.time()

        if _stop():
            sub_q.put({"type": "phase", "msg": f"[Thread {thread_id}] Stopped: {label}"})

        # Check if ALL threads are done/stopped → mark scan done
        all_done = all(t["status"] in ("done", "stopped") for t in scan.get("threads", {}).values())
        if all_done:
            scan["status"] = "done"
            sub_q.put({"type": "phase", "msg": f"[Thread {thread_id}] Complete: {label}"})
            sub_q.put({"type": "done", "results": scan["results"]})

    thread = threading.Thread(target=_run_sub_thread, daemon=True)
    thread.start()

    return jsonify({
        "ok": True,
        "scan_id": scan_id,
        "thread_id": thread_id,
        "label": label,
        "msg": f"Thread {thread_id} started for: {label}",
    })


@app.route("/api/scans/<scan_id>/threads")
def list_threads(scan_id: str):
    """List all sub-threads for a scan."""
    if scan_id not in scans:
        return jsonify({"error": "scan not found"}), 404
    return jsonify({"threads": scans[scan_id].get("threads", {})})


@app.route("/api/scans/<scan_id>/stop", methods=["POST"])
def stop_scan(scan_id: str):
    """Stop the main scan and all its sub-threads."""
    if scan_id not in scans:
        return jsonify({"error": "scan not found"}), 404

    # Signal main scan
    ce = cancel_events.get(scan_id)
    if ce:
        ce.set()

    # Signal all sub-threads
    for tid in scans[scan_id].get("threads", {}):
        sub_ce = cancel_events.get(f"{scan_id}:{tid}")
        if sub_ce:
            sub_ce.set()

    return jsonify({"ok": True, "msg": f"Stop signal sent to scan {scan_id} and all threads"})


@app.route("/api/scans/<scan_id>/threads/<thread_id>/stop", methods=["POST"])
def stop_thread(scan_id: str, thread_id: str):
    """Stop a single sub-thread within a scan."""
    if scan_id not in scans:
        return jsonify({"error": "scan not found"}), 404
    threads = scans[scan_id].get("threads", {})
    if thread_id not in threads:
        return jsonify({"error": "thread not found"}), 404

    key = f"{scan_id}:{thread_id}"
    ce = cancel_events.get(key)
    if ce:
        ce.set()
        return jsonify({"ok": True, "msg": f"Stop signal sent to thread {thread_id}"})
    else:
        return jsonify({"error": "no cancel event for this thread"}), 400


@app.route("/api/phishing/smtp", methods=["GET"])
def smtp_get():
    cfg = mailer.get_config()
    cfg["local_smtp_running"] = local_smtp.is_running()
    return jsonify(cfg)


@app.route("/api/phishing/smtp", methods=["POST"])
def smtp_save():
    mailer.save_config(request.get_json(force=True))
    return jsonify({"ok": True})


@app.route("/api/smtp/status")
def smtp_status():
    return jsonify({"running": local_smtp.is_running()})


@app.route("/api/smtp/log")
def smtp_log():
    return jsonify(local_smtp.get_log())


@app.route("/api/smtp/start", methods=["POST"])
def smtp_start():
    data = request.get_json(force=True) if request.is_json else {}
    port = int(data.get("port", 2525))
    domain = data.get("domain", "example.com")
    actual_port = local_smtp.start(port=port, domain=domain)
    # Auto-configure email_sender to use the local relay
    mailer.save_config({
        "host": "127.0.0.1",
        "port": actual_port,
        "user": f"relay@{domain}",
        "password": "local",
        "use_tls": False,
    })
    return jsonify({"ok": True, "port": actual_port})


@app.route("/api/smtp/stop", methods=["POST"])
def smtp_stop():
    local_smtp.stop()
    return jsonify({"ok": True})


@app.route("/api/phishing/send", methods=["POST"])
def phishing_send():
    data = request.get_json(force=True)
    result = mailer.send_email(
        to        = data.get("to", ""),
        subject   = data.get("subject", ""),
        body_html = data.get("body_html", ""),
        body_text = data.get("body_text", ""),
        from_addr = data.get("from_addr", ""),
        reply_to  = data.get("reply_to", ""),
    )
    return jsonify(result)


@app.route("/api/phishing/templates")
def phishing_templates():
    return jsonify(phishing_mod.list_templates())


@app.route("/api/phishing/generate", methods=["POST"])
def phishing_generate():
    data         = request.get_json(force=True)
    scan_id      = data.get("scan_id", "")
    template_key = data.get("template", "")

    if scan_id and scan_id in scans:
        scan = scans[scan_id]
    else:
        # Build a virtual scan from direct inputs so generation works without a scan
        scan = {
            "inputs": {
                "domain":      data.get("domain", "example.com"),
                "email":       data.get("email", ""),
                "company":     data.get("company", ""),
                "person_name": data.get("person_name", ""),
            },
            "results": {},
        }

    result = phishing_mod.generate(scan, template_key)
    return jsonify(result)


@app.route("/api/phishing/generate-for-profile", methods=["POST"])
def phishing_generate_for_profile():
    """Generate a phishing email body for a specific person profile using AI if available."""
    import urllib.request as _req
    data    = request.get_json(force=True)
    person  = data.get("person", {})
    template = data.get("template", "credential_reset")

    name   = person.get("name", "there")
    title  = person.get("title", "")
    dept   = person.get("department", "")
    email  = person.get("email", "")
    domain = (email.split("@")[1] if "@" in email else "")

    # Template defaults (fallback when no AI)
    _subjects = {
        "credential_reset": "Action Required: Verify your account credentials",
        "ceo_fraud":        "Urgent: Wire transfer authorization needed",
        "vpn_access":       "IT Notice: VPN certificate renewal required",
        "document_share":   "Shared document awaiting your review",
        "security_alert":   "Security Alert: Unusual sign-in detected",
        "it_helpdesk":      "IT Support: Password reset requested",
    }
    subject = _subjects.get(template, "Action Required")

    first = name.split()[0] if name else "there"

    # Try AI body generation
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    openai_key    = os.environ.get("OPENAI_API_KEY", "")

    body_html = ""
    body_text = ""

    if anthropic_key or openai_key:
        prompt = (
            f"You are a red team operator writing a phishing simulation email for an authorized engagement.\n"
            f"Write a convincing phishing email body for this target:\n"
            f"  Name: {name}\n"
            f"  Job title: {title or 'unknown'}\n"
            f"  Department: {dept or 'unknown'}\n"
            f"  Company domain: {domain or 'unknown'}\n"
            f"  Phishing template: {template}\n\n"
            f"Requirements:\n"
            f"- Address them by first name ({first})\n"
            f"- Match the template style: {template.replace('_',' ')}\n"
            f"- Sound like an internal IT or management communication\n"
            f"- Include a plausible call-to-action (click a link, verify credentials, etc.)\n"
            f"- Keep it under 200 words\n"
            f"- Return ONLY two sections separated by '---TEXT---':\n"
            f"  First: the HTML version (use simple <p> and <br> tags only)\n"
            f"  Second: the plain text version\n"
            f"Do not include subject line, greetings header, or any explanation."
        )

        try:
            if anthropic_key:
                model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
                body_bytes = json.dumps({
                    "model": model,
                    "max_tokens": 800,
                    "messages": [{"role": "user", "content": prompt}],
                }).encode()
                req = _req.Request(
                    "https://api.anthropic.com/v1/messages",
                    data=body_bytes,
                    headers={
                        "x-api-key": anthropic_key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    method="POST",
                )
                with _req.urlopen(req, timeout=30) as r:
                    resp = json.loads(r.read())
                raw = resp["content"][0]["text"].strip()
            else:
                body_bytes = json.dumps({
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 800,
                }).encode()
                req = _req.Request(
                    "https://api.openai.com/v1/chat/completions",
                    data=body_bytes,
                    headers={
                        "Authorization": f"Bearer {openai_key}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with _req.urlopen(req, timeout=30) as r:
                    resp = json.loads(r.read())
                raw = resp["choices"][0]["message"]["content"].strip()

            if "---TEXT---" in raw:
                parts = raw.split("---TEXT---", 1)
                body_html = parts[0].strip()
                body_text = parts[1].strip()
            else:
                body_html = raw
                body_text = re.sub(r'<[^>]+>', '', raw).strip()

        except Exception:
            body_html = ""  # fall through to template below

    # Fallback: simple template body
    if not body_html:
        body_html = (
            f"<p>Dear {first},</p>"
            f"<p>This is an automated notification from IT Security. "
            f"We have detected activity on your account that requires immediate verification.</p>"
            f"<p>Please click the link below to verify your credentials and avoid account suspension:</p>"
            f"<p><a href='#'>Verify my account &rarr;</a></p>"
            f"<p>This link expires in 24 hours.</p>"
            f"<p>IT Security Team</p>"
        )
        body_text = (
            f"Dear {first},\n\n"
            f"This is an automated notification from IT Security.\n"
            f"Please verify your credentials within 24 hours to avoid account suspension.\n\n"
            f"IT Security Team"
        )

    return jsonify({
        "subject":   subject,
        "body_html": body_html,
        "body_text": body_text,
        "to":        email,
        "from_suggestion": f"it-security@{domain}" if domain else "it-security@company.com",
        "ai_generated": bool(anthropic_key or openai_key) and bool(body_html),
    })


@app.route("/api/phishing/generate-page", methods=["POST"])
def phishing_generate_page():
    """Use AI to generate a phishing landing page HTML from a prompt."""
    import urllib.request as _req
    data   = request.get_json(force=True)
    prompt = data.get("prompt", "").strip()
    if not prompt:
        return jsonify({"error": "prompt required"}), 400

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    openai_key    = os.environ.get("OPENAI_API_KEY", "")

    if not anthropic_key and not openai_key:
        return jsonify({"error": "No AI API key configured. Set one in the AI Enhancement section."}), 400

    system = (
        "You are a red team operator creating phishing landing pages for authorized penetration testing engagements. "
        "Generate complete, self-contained HTML pages that look convincing. "
        "Use inline CSS only (no external stylesheets). "
        "Include a form with id='loginForm' that has inputs for username/email and password. "
        "The form action should be '#' and method 'POST'. "
        "Return ONLY the raw HTML — no markdown, no code fences, no explanation."
    )
    full_prompt = f"{system}\n\nUser request: {prompt}"

    try:
        if anthropic_key:
            model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
            body_bytes = json.dumps({
                "model": model,
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": full_prompt}],
            }).encode()
            req = _req.Request(
                "https://api.anthropic.com/v1/messages",
                data=body_bytes,
                headers={
                    "x-api-key": anthropic_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                method="POST",
            )
            with _req.urlopen(req, timeout=60) as r:
                resp = json.loads(r.read())
            html = resp["content"][0]["text"].strip()
        else:
            body_bytes = json.dumps({
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": full_prompt}],
                "max_tokens": 4096,
            }).encode()
            req = _req.Request(
                "https://api.openai.com/v1/chat/completions",
                data=body_bytes,
                headers={
                    "Authorization": f"Bearer {openai_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with _req.urlopen(req, timeout=60) as r:
                resp = json.loads(r.read())
            html = resp["choices"][0]["message"]["content"].strip()

        # Strip any accidental code fences
        if html.startswith("```"):
            html = re.sub(r"^```[a-z]*\n?", "", html)
            html = re.sub(r"\n?```$", "", html)

        return jsonify({"html": html})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/phishing/clone-page", methods=["POST"])
def clone_page():
    """Fetch a URL and return its HTML with forms repointed for credential capture."""
    import urllib.request as _req
    data = request.get_json(force=True)
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        req = _req.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/124.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*",
        })
        with _req.urlopen(req, context=ctx, timeout=15) as resp:
            charset = resp.headers.get_content_charset() or "utf-8"
            html = resp.read().decode(charset, errors="replace")

        # Parse base URL for making relative URLs absolute
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        # Make CSS/image links absolute so preview works
        html = re.sub(
            r'(href|src|action)=["\'](?!https?://|data:|#|javascript:)([^"\']+)["\']',
            lambda m: f'{m.group(1)}="{urljoin(base + "/", m.group(2))}"',
            html,
        )

        # Repoint all <form> actions to # (GoPhish will handle capture)
        html = re.sub(r'<form([^>]*?)action=["\'][^"\']*["\']', r'<form\1action="#"', html, flags=re.IGNORECASE)
        # Ensure method=POST
        html = re.sub(r'<form([^>]*?)method=["\'][^"\']*["\']', r'<form\1method="POST"', html, flags=re.IGNORECASE)

        return jsonify({"html": html, "original_url": url})
    except Exception as e:
        return jsonify({"error": f"Failed to fetch {url}: {e}"}), 500


@app.route("/api/scans")
def list_scans():
    summary = []
    for sid, s in scans.items():
        summary.append({
            "id": sid,
            "status": s["status"],
            "inputs": s["inputs"],
            "started_at": s["started_at"],
            "tool_count": len(s["results"]),
        })
    summary.sort(key=lambda x: x["started_at"], reverse=True)
    return jsonify(summary)


# ──────────────────────────────────────────────────────────────────────────────
# Web scraper routes
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/config/ai", methods=["POST"])
def config_ai():
    """Set AI API keys + model for the current server session (never stored to disk)."""
    data = request.get_json(force=True)
    if data.get("anthropic_key"):
        os.environ["ANTHROPIC_API_KEY"] = data["anthropic_key"].strip()
    if data.get("openai_key"):
        os.environ["OPENAI_API_KEY"] = data["openai_key"].strip()
    if data.get("anthropic_model"):
        os.environ["ANTHROPIC_MODEL"] = data["anthropic_model"].strip()
    status = {
        "anthropic":       bool(os.environ.get("ANTHROPIC_API_KEY")),
        "openai":          bool(os.environ.get("OPENAI_API_KEY")),
        "anthropic_model": os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
    }
    return jsonify({"ok": True, "status": status})


@app.route("/api/config/ai", methods=["GET"])
def config_ai_status():
    return jsonify({
        "anthropic":       bool(os.environ.get("ANTHROPIC_API_KEY")),
        "openai":          bool(os.environ.get("OPENAI_API_KEY")),
        "anthropic_model": os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6"),
    })


@app.route("/api/phishing/lookalike-domains", methods=["POST"])
def lookalike_domains():
    """Generate lookalike domain variations and check if they resolve (DNS)."""
    import socket
    data   = request.get_json(force=True)
    domain = data.get("domain", "").strip().lower().lstrip("www.")
    if not domain or "." not in domain:
        return jsonify({"error": "Invalid domain"}), 400

    name, _, tld = domain.rpartition(".")

    def _check(d):
        try:
            socket.getaddrinfo(d, None, proto=socket.IPPROTO_TCP)
            return True
        except OSError:
            return False

    # Build variation list
    variations = set()

    # Typosquat character substitutions
    subs = {"a":"4","e":"3","i":"1","l":"1","o":"0","s":"5","t":"7"}
    for i, ch in enumerate(name):
        if ch in subs:
            variations.add(name[:i] + subs[ch] + name[i+1:] + "." + tld)

    # Homoglyph lookalikes (visually similar chars)
    glyphs = {"a":"а","e":"е","o":"о","p":"р","c":"с","x":"х"}  # Cyrillic lookalikes
    for i, ch in enumerate(name):
        if ch in glyphs:
            variations.add(name[:i] + glyphs[ch] + name[i+1:] + "." + tld)

    # Extra words prepended / appended
    for prefix in ("secure-", "login-", "my-", "mail-", "portal-", "support-"):
        variations.add(prefix + domain)
    for suffix in ("-login", "-secure", "-portal", "-hr", "-mail"):
        variations.add(name + suffix + "." + tld)

    # Alternative TLDs
    for alt_tld in ("com", "net", "org", "co", "io", "info", "biz", "us"):
        if alt_tld != tld:
            variations.add(name + "." + alt_tld)

    # Double-letter / missing-letter
    for i, ch in enumerate(name):
        variations.add(name[:i] + ch + ch + name[i+1:] + "." + tld)  # double
        if len(name) > 3:
            variations.add(name[:i] + name[i+1:] + "." + tld)           # omit

    # Remove the original domain from variations
    variations.discard(domain)

    results = []
    for v in sorted(variations):
        registered = _check(v)
        results.append({"domain": v, "registered": registered})

    # Sort: registered first (interesting targets), then alphabetical
    results.sort(key=lambda x: (not x["registered"], x["domain"]))
    return jsonify({"original": domain, "variations": results[:60]})


@app.route("/api/scrape", methods=["POST"])
def scrape_website():
    """Standalone scrape — does not require an active scan."""
    import web_scraper as ws
    data = request.get_json(force=True)
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    if not url.startswith("http"):
        url = "https://" + url
    use_ai = data.get("ai", True)
    result = ws.scrape(url, ai=use_ai)
    return jsonify(result)


@app.route("/api/profiles/<scan_id>")
def get_profiles(scan_id):
    if scan_id not in scans:
        return jsonify({"error": "scan not found"}), 404
    return jsonify(profiles_mod.build_profiles(scans[scan_id]))


@app.route("/api/gophish/groups/from-scrape", methods=["POST"])
def gophish_group_from_scrape():
    """Create a GoPhish target group from web scrape results."""
    data    = request.get_json(force=True)
    people  = data.get("people", [])
    name    = data.get("name", "Scraped Targets")
    if not people:
        return jsonify({"error": "no people provided"}), 400
    new_targets = []
    for p in people:
        parts = p.get("name", "").split()
        first = parts[0] if parts else ""
        last  = " ".join(parts[1:]) if len(parts) > 1 else ""
        new_targets.append({
            "first_name": first,
            "last_name":  last,
            "email":      p.get("email", "") or (p.get("email_candidates", [""])[0]),
            "position":   p.get("department", "") or p.get("title", ""),
        })

    # Upsert: if a group with this name already exists, merge targets
    existing = gophish.list_groups()
    if isinstance(existing, list):
        for grp in existing:
            if grp.get("name") == name:
                # Merge: add only targets whose email isn't already in the group
                existing_emails = {t.get("email", "").lower() for t in (grp.get("targets") or [])}
                merged = list(grp.get("targets") or [])
                for t in new_targets:
                    if t["email"].lower() not in existing_emails:
                        merged.append(t)
                        existing_emails.add(t["email"].lower())
                result = gophish.update_group(grp["id"], name, merged)
                result["_merged"] = True
                return jsonify(result)

    return jsonify(gophish.create_group(name, new_targets))


# ──────────────────────────────────────────────────────────────────────────────
# GoPhish bridge routes
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/gophish/status")
def gophish_status():
    return jsonify(gophish.ping())


@app.route("/api/gophish/config", methods=["POST"])
def gophish_config():
    data = request.get_json(force=True)
    if "api_key" in data:
        gophish.set_key(data["api_key"])
    if "url" in data:
        gophish.GOPHISH_URL = data["url"]
    if "phish_url" in data:
        gophish.PHISH_SERVER = data["phish_url"]
    return jsonify({"ok": True})


# Pages
@app.route("/api/gophish/pages")
def gophish_pages():
    return jsonify(gophish.list_pages())

@app.route("/api/gophish/pages", methods=["POST"])
def gophish_pages_create():
    d = request.get_json(force=True)
    return jsonify(gophish.create_page(
        name=d.get("name", ""),
        html=d.get("html", ""),
        capture_credentials=d.get("capture_credentials", True),
        capture_passwords=d.get("capture_passwords", True),
        redirect_url=d.get("redirect_url", ""),
    ))

@app.route("/api/gophish/pages/<int:page_id>", methods=["PUT"])
def gophish_pages_update(page_id):
    d = request.get_json(force=True)
    return jsonify(gophish.update_page(
        page_id=page_id,
        name=d.get("name", ""),
        html=d.get("html", ""),
        capture_credentials=d.get("capture_credentials", True),
        capture_passwords=d.get("capture_passwords", True),
        redirect_url=d.get("redirect_url", ""),
    ))

@app.route("/api/gophish/pages/<int:page_id>", methods=["DELETE"])
def gophish_pages_delete(page_id):
    return jsonify(gophish.delete_page(page_id))


# Email templates
@app.route("/api/gophish/templates")
def gophish_templates():
    return jsonify(gophish.list_templates())

@app.route("/api/gophish/templates", methods=["POST"])
def gophish_templates_create():
    d = request.get_json(force=True)
    return jsonify(gophish.create_template(
        name=d.get("name", ""),
        subject=d.get("subject", ""),
        html=d.get("html", ""),
        text=d.get("text", ""),
        envelope_sender=d.get("envelope_sender", ""),
    ))

@app.route("/api/gophish/templates/<int:tpl_id>", methods=["PUT"])
def gophish_templates_update(tpl_id):
    d = request.get_json(force=True)
    return jsonify(gophish.update_template(
        tpl_id=tpl_id,
        name=d.get("name", ""),
        subject=d.get("subject", ""),
        html=d.get("html", ""),
        text=d.get("text", ""),
        envelope_sender=d.get("envelope_sender", ""),
    ))

@app.route("/api/gophish/templates/<int:tpl_id>", methods=["DELETE"])
def gophish_templates_delete(tpl_id):
    return jsonify(gophish.delete_template(tpl_id))


# Sending profiles
@app.route("/api/gophish/smtp")
def gophish_smtp():
    return jsonify(gophish.list_smtp())

@app.route("/api/gophish/smtp", methods=["POST"])
def gophish_smtp_create():
    d = request.get_json(force=True)
    return jsonify(gophish.create_smtp(
        name=d.get("name", ""),
        host=d.get("host", ""),
        port=int(d.get("port", 587)),
        username=d.get("username", ""),
        password=d.get("password", ""),
        from_address=d.get("from_address", ""),
        use_tls=d.get("use_tls", True),
    ))

@app.route("/api/gophish/smtp/<int:smtp_id>", methods=["DELETE"])
def gophish_smtp_delete(smtp_id):
    return jsonify(gophish.delete_smtp(smtp_id))


# Target groups
@app.route("/api/gophish/groups")
def gophish_groups():
    return jsonify(gophish.list_groups())

@app.route("/api/gophish/groups", methods=["POST"])
def gophish_groups_create():
    d = request.get_json(force=True)
    return jsonify(gophish.create_group(
        name=d.get("name", ""),
        targets=d.get("targets", []),
    ))

@app.route("/api/gophish/groups/from-scan/<scan_id>", methods=["POST"])
def gophish_group_from_scan(scan_id):
    """Create a target group from email_enum results of an OSINT scan."""
    if scan_id not in scans:
        return jsonify({"error": "scan not found"}), 404
    results  = scans[scan_id].get("results", {})
    enum     = results.get("email_enum", {})
    valid    = enum.get("valid", [])
    if not valid:
        return jsonify({"error": "no valid emails in scan"}), 400
    targets = [{"first_name": e.split("@")[0], "last_name": "",
                "email": e, "position": ""} for e in valid]
    d    = request.get_json(force=True) or {}
    name = d.get("name") or f"Scan {scan_id} — {scans[scan_id]['inputs'].get('domain','')}"
    return jsonify(gophish.create_group(name, targets))

@app.route("/api/gophish/groups/<int:group_id>", methods=["DELETE"])
def gophish_groups_delete(group_id):
    return jsonify(gophish.delete_group(group_id))


# Campaigns
@app.route("/api/gophish/campaigns")
def gophish_campaigns():
    return jsonify(gophish.list_campaigns())

@app.route("/api/gophish/campaigns", methods=["POST"])
def gophish_campaigns_create():
    d = request.get_json(force=True)
    return jsonify(gophish.create_campaign(
        name=d.get("name", ""),
        template_id=int(d.get("template_id", 0)),
        page_id=int(d.get("page_id", 0)),
        smtp_id=int(d.get("smtp_id", 0)),
        group_id=int(d.get("group_id", 0)),
        url=d.get("url", ""),
        launch_date=d.get("launch_date", ""),
    ))

@app.route("/api/gophish/campaigns/<int:campaign_id>")
def gophish_campaign_detail(campaign_id):
    return jsonify(gophish.get_campaign(campaign_id))

@app.route("/api/gophish/campaigns/<int:campaign_id>/results")
def gophish_campaign_results(campaign_id):
    return jsonify(gophish.get_campaign_results(campaign_id))

@app.route("/api/gophish/campaigns/<int:campaign_id>/complete", methods=["POST"])
def gophish_campaign_complete(campaign_id):
    return jsonify(gophish.complete_campaign(campaign_id))

@app.route("/api/gophish/campaigns/<int:campaign_id>/restart", methods=["POST"])
def gophish_campaign_restart(campaign_id):
    """Complete the campaign then recreate it with the same config so the page goes live again."""
    old = gophish.get_campaign(campaign_id)
    if "error" in old:
        return jsonify(old), 404

    # Save names before touching the campaign — GoPhish works more
    # reliably with name-based refs than IDs.
    name          = old["name"]
    template_name = old["template"]["name"]
    page_name     = old["page"]["name"]
    smtp_name     = old["smtp"]["name"]
    url           = old.get("url", "")

    # Get group name — completed campaigns lose their 'groups' key,
    # so rebuild a target group from the results list.
    group_name = None
    if old.get("groups") and len(old["groups"]) > 0:
        group_name = old["groups"][0]["name"]
    else:
        targets = []
        for r in old.get("results", []):
            targets.append({
                "first_name": r.get("first_name", ""),
                "last_name":  r.get("last_name", ""),
                "email":      r.get("email", ""),
                "position":   r.get("position", ""),
            })
        if not targets:
            return jsonify({"error": "No targets found in old campaign"}), 400
        grp_name = f"{name} targets"
        grp = gophish.create_group(grp_name, targets)
        if "error" in grp:
            return jsonify(grp), 500
        group_name = grp_name

    # Complete the old campaign (if still active)
    if old.get("status") != "Completed":
        gophish.complete_campaign(campaign_id)

    # Strip any previous restart suffix, use fresh timestamp to avoid name conflicts
    import re as _re
    base_name = _re.sub(r'\s*#\d+$', '', name)

    # Recreate with same settings — launches immediately
    new = gophish.create_campaign(
        name          = f"{base_name} #{int(time.time()) % 100000}",
        template_name = template_name,
        page_name     = page_name,
        smtp_name     = smtp_name,
        group_name    = group_name,
        url           = url,
    )
    return jsonify(new)

@app.route("/api/gophish/campaigns/<int:campaign_id>", methods=["DELETE"])
def gophish_campaign_delete(campaign_id):
    return jsonify(gophish.delete_campaign(campaign_id))


# ──────────────────────────────────────────────────────────────────────────────
# Vishing routes
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/vishing/scripts")
def vishing_scripts():
    return jsonify(vishing_mod.list_scripts())


@app.route("/api/vishing/generate", methods=["POST"])
def vishing_generate():
    data       = request.get_json(force=True)
    scan_id    = data.get("scan_id", "")
    script_key = data.get("script", "")
    if scan_id not in scans:
        return jsonify({"error": "scan not found"}), 404
    return jsonify(vishing_mod.generate(scans[scan_id], script_key))


@app.route("/api/vishing/generate-for-person", methods=["POST"])
def vishing_generate_for_person():
    """Generate a vishing script for a specific person (no scan required)."""
    data       = request.get_json(force=True)
    script_key = data.get("script", "")
    person     = data.get("person", {})
    # Build a minimal fake scan from the person dict
    fake_scan = {
        "inputs": {
            "person_name": person.get("name", ""),
            "email":       person.get("email", ""),
            "company":     person.get("company", ""),
            "domain":      person.get("domain", ""),
        },
        "results": {},
    }
    return jsonify(vishing_mod.generate(fake_scan, script_key))


@app.route("/api/vishing/config", methods=["GET"])
def vishing_config_get():
    return jsonify({
        "account_sid":      bool(os.environ.get("TWILIO_ACCOUNT_SID")),
        "auth_token":       bool(os.environ.get("TWILIO_AUTH_TOKEN")),
        "caller_id":        os.environ.get("TWILIO_CALLER_ID", ""),
        "elevenlabs":       bool(os.environ.get("ELEVENLABS_API_KEY")),
        "elevenlabs_voice": os.environ.get("ELEVENLABS_VOICE_ID", ""),
    })


@app.route("/api/vishing/config", methods=["POST"])
def vishing_config_set():
    data = request.get_json(force=True)
    if data.get("account_sid"):
        os.environ["TWILIO_ACCOUNT_SID"] = data["account_sid"].strip()
    if data.get("auth_token"):
        os.environ["TWILIO_AUTH_TOKEN"] = data["auth_token"].strip()
    if data.get("caller_id"):
        os.environ["TWILIO_CALLER_ID"] = data["caller_id"].strip()
    if data.get("elevenlabs_key"):
        os.environ["ELEVENLABS_API_KEY"] = data["elevenlabs_key"].strip()
    if data.get("elevenlabs_voice"):
        os.environ["ELEVENLABS_VOICE_ID"] = data["elevenlabs_voice"].strip()
    return jsonify({"ok": True,
                    "account_sid":      bool(os.environ.get("TWILIO_ACCOUNT_SID")),
                    "auth_token":       bool(os.environ.get("TWILIO_AUTH_TOKEN")),
                    "caller_id":        os.environ.get("TWILIO_CALLER_ID", ""),
                    "elevenlabs":       bool(os.environ.get("ELEVENLABS_API_KEY")),
                    "elevenlabs_voice": os.environ.get("ELEVENLABS_VOICE_ID", "")})


# ──────────────────────────────────────────────────────────────────────────────
# VoIP / SIP routes
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/voip/sip/config", methods=["GET"])
def voip_sip_status():
    return jsonify(voip_mod.get_sip_status())


@app.route("/api/voip/sip/config", methods=["POST"])
def voip_sip_configure():
    data = request.get_json(force=True)
    result = voip_mod.configure_sip(data)
    return jsonify(result)


@app.route("/api/voip/call", methods=["POST"])
def voip_originate():
    """Originate a call via SIP/Twilio/manual."""
    data = request.get_json(force=True)
    record = voip_mod.originate_call(
        target_phone=data.get("phone", ""),
        caller_id=data.get("caller_id", ""),
        audio_url=data.get("audio_url", ""),
        ivr_flow_id=data.get("ivr_flow_id", ""),
        campaign_id=data.get("campaign_id", ""),
        target_name=data.get("name", ""),
        method=data.get("method", "auto"),
    )
    return jsonify({
        "call_id": record.call_id,
        "status": record.status,
        "method": record.method,
        "twilio_sid": record.twilio_sid,
    })


@app.route("/api/voip/calls", methods=["GET"])
def voip_active_calls():
    return jsonify(voip_mod.get_active_calls())


@app.route("/api/voip/calls/<call_id>", methods=["GET"])
def voip_get_call(call_id):
    record = voip_mod.get_call(call_id)
    if not record:
        return jsonify({"error": "Call not found"}), 404
    return jsonify({
        "call_id": record.call_id,
        "target_phone": record.target_phone,
        "target_name": record.target_name,
        "status": record.status,
        "method": record.method,
        "dtmf_digits": record.dtmf_digits,
        "dtmf_log": record.dtmf_log,
        "ivr_data": record.ivr_data,
        "duration": record.duration,
        "recording_path": record.recording_path,
        "amd_result": record.amd_result,
        "started_at": record.started_at,
        "ended_at": record.ended_at,
    })


@app.route("/api/voip/calls/<call_id>/hangup", methods=["POST"])
def voip_hangup(call_id):
    return jsonify(voip_mod.hangup_call(call_id))


@app.route("/api/voip/calls/<call_id>/hold", methods=["POST"])
def voip_hold(call_id):
    return jsonify(voip_mod.hold_call(call_id))


@app.route("/api/voip/calls/<call_id>/resume", methods=["POST"])
def voip_resume(call_id):
    data = request.get_json(force=True) if request.is_json else {}
    return jsonify(voip_mod.resume_call(call_id, data.get("audio_url", "")))


@app.route("/api/voip/calls/<call_id>/transfer", methods=["POST"])
def voip_transfer(call_id):
    data = request.get_json(force=True)
    return jsonify(voip_mod.transfer_call(call_id, data.get("target", "")))


@app.route("/api/voip/calls/<call_id>/dtmf", methods=["POST"])
def voip_send_dtmf(call_id):
    data = request.get_json(force=True)
    return jsonify(voip_mod.send_dtmf(call_id, data.get("digits", "")))


@app.route("/api/voip/calls/<call_id>/conference", methods=["POST"])
def voip_conference(call_id):
    data = request.get_json(force=True) if request.is_json else {}
    return jsonify(voip_mod.conference_call(call_id, data.get("room", "")))


# IVR flow management
@app.route("/api/voip/ivr/flows", methods=["GET"])
def voip_ivr_list():
    return jsonify(voip_mod.list_ivr_flows())


@app.route("/api/voip/ivr/flows", methods=["POST"])
def voip_ivr_create():
    data = request.get_json(force=True)
    return jsonify(voip_mod.create_ivr_flow(data.get("flow_id", ""), data.get("nodes", [])))


@app.route("/api/voip/ivr/flows/<flow_id>", methods=["GET"])
def voip_ivr_get(flow_id):
    return jsonify(voip_mod.get_ivr_flow(flow_id))


@app.route("/api/vishing/ivr/response", methods=["POST"])
def voip_ivr_response():
    """Twilio webhook: handles DTMF/speech input during IVR call."""
    call_id = request.args.get("call_id", "")
    flow_id = request.args.get("flow_id", "")
    node_id = request.args.get("node_id", "")
    digits = request.form.get("Digits", "") or request.args.get("digits", "")
    speech = request.form.get("SpeechResult", "")

    # Handle timeout (repeat node)
    if request.args.get("timeout") == "true" and not digits:
        flow = voip_mod._ivr_flows.get(flow_id, {})
        node = flow.get(node_id)
        if node:
            base_url = os.environ.get("VISHING_CALLBACK_URL", "")
            twiml = voip_mod._build_ivr_twiml(node, call_id, "", flow_id, base_url)
            return Response(twiml, content_type="application/xml")
        return Response('<Response><Hangup/></Response>', content_type="application/xml")

    twiml = voip_mod.process_ivr_input(call_id, flow_id, node_id, digits, speech)
    return Response(twiml, content_type="application/xml")


@app.route("/api/vishing/twilio-callback/<call_id>", methods=["POST"])
def voip_twilio_callback(call_id):
    """Twilio status callback for VoIP calls."""
    voip_mod.handle_twilio_callback(call_id, request.form.to_dict())
    return "", 204


# Batch calling
@app.route("/api/voip/batch", methods=["POST"])
def voip_batch_start():
    data = request.get_json(force=True)
    result = voip_mod.start_batch_calls(
        targets=data.get("targets", []),
        campaign_id=data.get("campaign_id", ""),
        caller_id=data.get("caller_id", ""),
        audio_url=data.get("audio_url", ""),
        ivr_flow_id=data.get("ivr_flow_id", ""),
        delay_seconds=data.get("delay", 30),
        method=data.get("method", "auto"),
    )
    return jsonify(result)


@app.route("/api/voip/batch/<batch_id>", methods=["GET"])
def voip_batch_status(batch_id):
    return jsonify(voip_mod.get_batch_status(batch_id))


@app.route("/api/voip/batch/<batch_id>/stop", methods=["POST"])
def voip_batch_stop(batch_id):
    return jsonify(voip_mod.stop_batch(batch_id))


# ──────────────────────────────────────────────────────────────────────────────
# Call transcription & voice library
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/voip/calls/<call_id>/transcribe", methods=["POST"])
def voip_transcribe(call_id):
    """Transcribe a call recording using Whisper API or Twilio transcription."""
    record = voip_mod.get_call(call_id)
    if not record:
        return jsonify({"error": "Call not found"}), 404
    if not record.recording_path:
        return jsonify({"error": "No recording available"}), 400

    # Try OpenAI Whisper API
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    if openai_key:
        try:
            recording_file = record.recording_path
            if recording_file.startswith("/static/"):
                recording_file = os.path.join(os.path.dirname(__file__), recording_file.lstrip("/"))

            # Download Twilio recording if URL
            if recording_file.startswith("http"):
                import tempfile
                req = urllib.request.Request(recording_file + ".mp3")
                with urllib.request.urlopen(req, timeout=30) as resp:
                    audio_data = resp.read()
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".mp3")
                tmp.write(audio_data)
                tmp.close()
                recording_file = tmp.name

            # Call Whisper API
            import subprocess
            result = subprocess.run(
                ["curl", "-s", "https://api.openai.com/v1/audio/transcriptions",
                 "-H", f"Authorization: Bearer {openai_key}",
                 "-F", f"file=@{recording_file}",
                 "-F", "model=whisper-1"],
                capture_output=True, text=True, timeout=120,
            )
            data = json.loads(result.stdout)
            transcription = data.get("text", "")
            record.transcription = transcription
            return jsonify({"ok": True, "transcription": transcription})
        except Exception as e:
            return jsonify({"error": f"Transcription failed: {e}"}), 500
    else:
        return jsonify({"error": "No OPENAI_API_KEY configured for Whisper transcription"}), 400


@app.route("/api/voip/voice-library", methods=["GET"])
def voice_library_list():
    """List all saved audio clips in the voice library."""
    audio_dir = os.path.join(os.path.dirname(__file__), "static", "vishing_audio")
    clips = []
    if os.path.isdir(audio_dir):
        for f in sorted(os.listdir(audio_dir), reverse=True):
            if f.endswith((".mp3", ".wav")):
                path = os.path.join(audio_dir, f)
                clips.append({
                    "filename": f,
                    "url": f"/static/vishing_audio/{f}",
                    "size": os.path.getsize(path),
                    "created": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(os.path.getctime(path))),
                })
    return jsonify(clips)


@app.route("/api/voip/voice-library/<filename>", methods=["DELETE"])
def voice_library_delete(filename):
    """Delete an audio clip from the voice library."""
    audio_dir = os.path.join(os.path.dirname(__file__), "static", "vishing_audio")
    path = os.path.join(audio_dir, os.path.basename(filename))
    if os.path.isfile(path):
        os.unlink(path)
        return jsonify({"ok": True})
    return jsonify({"error": "File not found"}), 404


@app.route("/api/voip/voice-library/upload", methods=["POST"])
def voice_library_upload():
    """Upload a custom audio clip to the voice library."""
    if "audio" not in request.files:
        return jsonify({"error": "No audio file"}), 400
    f = request.files["audio"]
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in (".mp3", ".wav", ".ogg", ".m4a"):
        return jsonify({"error": "Invalid audio format"}), 400
    audio_dir = os.path.join(os.path.dirname(__file__), "static", "vishing_audio")
    filename = f"{uuid.uuid4().hex[:8]}{ext}"
    f.save(os.path.join(audio_dir, filename))
    return jsonify({"ok": True, "url": f"/static/vishing_audio/{filename}", "filename": filename})


# ──────────────────────────────────────────────────────────────────────────────
# Call event streaming (SSE for live call monitoring)
# ──────────────────────────────────────────────────────────────────────────────

_call_event_queues: dict[str, queue.Queue] = {}


def _call_event_handler(event):
    """Broadcast call events to all SSE listeners."""
    for q in list(_call_event_queues.values()):
        try:
            q.put_nowait(event)
        except queue.Full:
            pass


# Register the handler
voip_mod.on_call_event(_call_event_handler)


@app.route("/api/voip/events")
def voip_event_stream():
    """SSE stream for live call events (status, DTMF, recordings)."""
    listener_id = uuid.uuid4().hex[:8]
    q = queue.Queue(maxsize=200)
    _call_event_queues[listener_id] = q

    def generate():
        try:
            while True:
                try:
                    event = q.get(timeout=30)
                    yield f"data: {json.dumps(event)}\n\n"
                except queue.Empty:
                    yield f"data: {json.dumps({'type': 'ping'})}\n\n"
        finally:
            _call_event_queues.pop(listener_id, None)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/vishing/generate-ai", methods=["POST"])
def vishing_generate_ai():
    """Use Claude or OpenAI to write a fully personalised vishing call script."""
    data       = request.get_json(force=True)
    script_key = data.get("script", "it_support")
    person     = data.get("person", {})
    scan_id    = data.get("scan_id", "")

    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    openai_key    = os.environ.get("OPENAI_API_KEY", "")
    if not anthropic_key and not openai_key:
        return jsonify({"error": "No AI API key configured — set one in AI Enhancement settings"}), 400

    # Gather context
    if scan_id and scan_id in scans:
        ctx = vishing_mod.build_context(scans[scan_id])
    else:
        fake_scan = {"inputs": {
            "person_name": person.get("name", ""),
            "email":       person.get("email", ""),
            "company":     person.get("company", ""),
            "domain":      person.get("domain", ""),
        }, "results": {}}
        ctx = vishing_mod.build_context(fake_scan)

    script_meta = vishing_mod.SCRIPTS.get(script_key, {})
    pretext     = script_meta.get("key", script_key)

    prompt = (
        "You are a senior red team operator writing a vishing (voice phishing) call script "
        "for an AUTHORIZED penetration testing engagement.\n\n"
        f"Pretext / scenario: {pretext.replace('_', ' ')}\n"
        f"Target first name: {ctx['first_name']}\n"
        f"Target company: {ctx['company']}\n"
        f"Target domain: {ctx['domain']}\n"
        f"Target email: {ctx['email'] or 'unknown'}\n"
        f"Target position: {ctx['position'] or 'unknown'}\n"
        f"Known breaches: {', '.join(ctx['breaches']) if ctx['breaches'] else 'none'}\n\n"
        "Write a detailed, realistic call script with these labelled sections:\n"
        "=== OPENING ===\n"
        "=== PRETEXT ===\n"
        "=== KEY QUESTIONS ===\n"
        "=== OBJECTIONS ===\n"
        "=== CLOSING ===\n\n"
        "Rules:\n"
        "- Use the target's first name naturally throughout\n"
        "- Reference the company and domain specifically\n"
        "- Include plausible-sounding ticket/case numbers and internal system names\n"
        "- Keep quoted speech in double quotes\n"
        "- Stage directions in [square brackets]\n"
        "- Aim for 300-500 words total\n"
        "Return ONLY the script sections, no preamble."
    )

    try:
        if anthropic_key:
            model     = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
            body_bytes = json.dumps({
                "model": model, "max_tokens": 1500,
                "messages": [{"role": "user", "content": prompt}],
            }).encode()
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=body_bytes,
                headers={"x-api-key": anthropic_key, "anthropic-version": "2023-06-01",
                         "content-type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=45) as r:
                script_text = json.loads(r.read())["content"][0]["text"].strip()
        else:
            body_bytes = json.dumps({
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1500,
            }).encode()
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=body_bytes,
                headers={"Authorization": f"Bearer {openai_key}",
                         "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=45) as r:
                script_text = json.loads(r.read())["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Merge AI text into the standard template result structure
    base = vishing_mod.generate(
        {"inputs": {"person_name": ctx["full_name"], "email": ctx["email"],
                    "company": ctx["company"], "domain": ctx["domain"]},
         "results": {}},
        script_key,
    )
    base["script"]       = script_text
    base["ai_generated"] = True
    return jsonify(base)


@app.route("/api/vishing/elevenlabs/voices")
def vishing_elevenlabs_voices():
    """Fetch available voices from ElevenLabs."""
    key = os.environ.get("ELEVENLABS_API_KEY", "")
    if not key:
        return jsonify({"error": "ELEVENLABS_API_KEY not set"}), 400
    try:
        req = urllib.request.Request(
            "https://api.elevenlabs.io/v1/voices",
            headers={"xi-api-key": key, "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read())
        voices = [{"id": v["voice_id"], "name": v["name"],
                   "category": v.get("category", ""),
                   "preview": v.get("preview_url", "")}
                  for v in data.get("voices", [])]
        voices.sort(key=lambda v: v["name"])
        return jsonify({"voices": voices})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/vishing/elevenlabs/generate", methods=["POST"])
def vishing_elevenlabs_generate():
    """Generate audio from text using ElevenLabs TTS and save to static/vishing_audio/."""
    import hashlib
    key      = os.environ.get("ELEVENLABS_API_KEY", "")
    voice_id = os.environ.get("ELEVENLABS_VOICE_ID", "")
    if not key:
        return jsonify({"error": "ELEVENLABS_API_KEY not set"}), 400

    data     = request.get_json(force=True)
    text     = data.get("text", "").strip()
    voice_id = data.get("voice_id", voice_id).strip()
    model    = data.get("model", "eleven_multilingual_v2")

    if not text:
        return jsonify({"error": "text required"}), 400
    if not voice_id:
        return jsonify({"error": "voice_id required — select a voice first"}), 400

    # Stable filename based on content hash so repeats reuse cached audio
    h        = hashlib.sha1((text + voice_id + model).encode()).hexdigest()[:16]
    filename = f"{h}.mp3"
    out_dir  = os.path.join(os.path.dirname(__file__), "static", "vishing_audio")
    out_path = os.path.join(out_dir, filename)

    if not os.path.exists(out_path):
        body = json.dumps({
            "text":  text,
            "model_id": model,
            "voice_settings": {"stability": 0.5, "similarity_boost": 0.75},
        }).encode()
        req = urllib.request.Request(
            f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}",
            data=body,
            headers={
                "xi-api-key":    key,
                "Content-Type":  "application/json",
                "Accept":        "audio/mpeg",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                audio_bytes = r.read()
        except urllib.error.HTTPError as e:
            return jsonify({"error": f"ElevenLabs API error {e.code}: {e.read().decode()}"}), 500
        except Exception as e:
            return jsonify({"error": str(e)}), 500

        with open(out_path, "wb") as f:
            f.write(audio_bytes)

    audio_url = f"/static/vishing_audio/{filename}"
    return jsonify({"ok": True, "url": audio_url, "filename": filename})


@app.route("/api/vishing/campaigns")
def vishing_list_campaigns():
    out = []
    for c in vishing_campaigns.values():
        out.append({
            "id":         c["id"],
            "name":       c["name"],
            "script_key": c["script_key"],
            "target_count": len(c["targets"]),
            "call_count": len(c["calls"]),
            "created":    c["created"],
        })
    out.sort(key=lambda x: x["created"], reverse=True)
    return jsonify(out)


@app.route("/api/vishing/campaigns", methods=["POST"])
def vishing_create_campaign():
    data = request.get_json(force=True)
    cid  = uuid.uuid4().hex[:10]
    vishing_campaigns[cid] = {
        "id":         cid,
        "name":       data.get("name", f"Vishing Campaign {cid}"),
        "script_key": data.get("script_key", ""),
        "caller_id":  data.get("caller_id", os.environ.get("TWILIO_CALLER_ID", "")),
        "targets":    data.get("targets", []),  # [{name, phone, context}]
        "calls":      [],
        "created":    time.time(),
    }
    return jsonify({"ok": True, "id": cid})


@app.route("/api/vishing/campaigns/<campaign_id>")
def vishing_get_campaign(campaign_id):
    c = vishing_campaigns.get(campaign_id)
    if not c:
        return jsonify({"error": "not found"}), 404
    # Ensure opener_audio_url is always present in the response
    out = dict(c)
    out.setdefault("opener_audio_url", "")
    return jsonify(out)


@app.route("/api/vishing/campaigns/<campaign_id>", methods=["DELETE"])
def vishing_delete_campaign(campaign_id):
    vishing_campaigns.pop(campaign_id, None)
    return jsonify({"ok": True})


@app.route("/api/vishing/campaigns/<campaign_id>/call", methods=["POST"])
def vishing_make_call(campaign_id):
    """Initiate a Twilio call for a target in the campaign."""
    c = vishing_campaigns.get(campaign_id)
    if not c:
        return jsonify({"error": "campaign not found"}), 404

    data         = request.get_json(force=True)
    target_phone = data.get("phone", "").strip()
    target_name  = data.get("name", "").strip()
    notes        = data.get("notes", "")

    if not target_phone:
        return jsonify({"error": "phone required"}), 400

    sid    = os.environ.get("TWILIO_ACCOUNT_SID", "")
    token  = os.environ.get("TWILIO_AUTH_TOKEN", "")
    caller = data.get("caller_id") or c.get("caller_id") or os.environ.get("TWILIO_CALLER_ID", "")

    call_entry = {
        "id":          uuid.uuid4().hex[:8],
        "target_phone": target_phone,
        "target_name":  target_name,
        "caller_id":    caller,
        "status":       "manual",
        "outcome":      "",
        "notes":        notes,
        "called_at":    time.time(),
        "twilio_sid":   None,
    }

    if sid and token and caller:
        try:
            from twilio.rest import Client
            client = Client(sid, token)
            # Use ElevenLabs audio if available, otherwise fall back to <Say>
            audio_url = data.get("audio_url", "") or c.get("opener_audio_url", "")
            if audio_url:
                abs_audio = request.host_url.rstrip("/") + audio_url if audio_url.startswith("/") else audio_url
                twiml = f"<Response><Play>{abs_audio}</Play><Pause length='30'/></Response>"
            else:
                twiml = "<Response><Say>This is a call from your IT support team. Please hold.</Say><Pause length='60'/></Response>"
            tw_call  = client.calls.create(
                to=target_phone,
                from_=caller,
                twiml=twiml,
                record=True,
                status_callback=request.host_url.rstrip("/") + f"/api/vishing/callback/{campaign_id}/{call_entry['id']}",
                status_callback_method="POST",
            )
            call_entry["twilio_sid"] = tw_call.sid
            call_entry["status"]     = tw_call.status
        except ImportError:
            call_entry["status"] = "no_twilio"
        except Exception as e:
            call_entry["status"] = "error"
            call_entry["notes"]  = str(e)
    else:
        call_entry["status"] = "manual"  # Twilio not configured — log manually

    c["calls"].append(call_entry)
    return jsonify({"ok": True, "call": call_entry})


@app.route("/api/vishing/callback/<campaign_id>/<call_id>", methods=["POST"])
def vishing_callback(campaign_id, call_id):
    """Twilio status callback — update call log."""
    c = vishing_campaigns.get(campaign_id)
    if c:
        for call in c["calls"]:
            if call["id"] == call_id:
                call["status"]    = request.form.get("CallStatus", call["status"])
                recording_url     = request.form.get("RecordingUrl", "")
                if recording_url:
                    call["recording"] = recording_url
                break
    return "", 204


@app.route("/api/vishing/campaigns/<campaign_id>/opener", methods=["POST"])
def vishing_set_opener(campaign_id):
    """Attach an ElevenLabs-generated audio URL as the call opener for this campaign."""
    c = vishing_campaigns.get(campaign_id)
    if not c:
        return jsonify({"error": "campaign not found"}), 404
    data = request.get_json(force=True)
    c["opener_audio_url"] = data.get("audio_url", "")
    return jsonify({"ok": True})


@app.route("/api/vishing/campaigns/<campaign_id>/calls/<call_id>", methods=["PATCH"])
def vishing_update_call(campaign_id, call_id):
    """Update outcome / notes for a call entry (manual logging)."""
    c = vishing_campaigns.get(campaign_id)
    if not c:
        return jsonify({"error": "campaign not found"}), 404
    data = request.get_json(force=True)
    for call in c["calls"]:
        if call["id"] == call_id:
            if "outcome" in data:
                call["outcome"] = data["outcome"]
            if "notes" in data:
                call["notes"] = data["notes"]
            if "status" in data:
                call["status"] = data["status"]
            return jsonify({"ok": True, "call": call})
    return jsonify({"error": "call not found"}), 404


# ──────────────────────────────────────────────────────────────────────────────
# Scan orchestration
# ──────────────────────────────────────────────────────────────────────────────

def _run_scan(scan_id: str, data: dict):
    q = scan_queues[scan_id]
    ce = cancel_events.get(scan_id)
    runner = ToolRunner(scan_id, q, cancel_event=ce)

    person_name: str = data.get("person_name", "").strip()
    username: str    = data.get("username", "").strip()
    email: str       = data.get("email", "").strip()
    company: str     = data.get("company", "").strip()
    domain: str      = data.get("domain", "").strip().lstrip("@")
    phone: str       = data.get("phone", "").strip()

    # Tool group filtering: "all" (default), "username", "email", "domain", "person", "company"
    tool_group: str  = data.get("tool_group", "all").strip().lower()
    # Individual tool skip list: ["sherlock", "holehe", ...]
    skip_tools: set  = set(data.get("skip_tools", []))

    def _should_run(tool_name: str, group: str) -> bool:
        """Check if a tool should run based on tool_group and skip_tools."""
        if tool_name in skip_tools:
            return False
        if tool_group == "all":
            return True
        return tool_group == group

    results = {}

    # ── Collectors: discovered intel gets chained to later phases ─────────
    discovered_usernames: set = set()
    discovered_emails: set    = set()
    discovered_names: set     = set()

    if username:
        discovered_usernames.add(username)
    if email:
        discovered_emails.add(email)
    if person_name:
        discovered_names.add(person_name)

    def _extract_name_from_email(em: str) -> str:
        """j.doe@domain → John Doe (best guess)."""
        local = em.split("@")[0].lower()
        # skip generic prefixes
        if local in ("info", "admin", "support", "contact", "hello", "noreply",
                     "sales", "hr", "press", "careers", "hse"):
            return ""
        # j.smith or jsmith patterns
        import re as _re
        m = _re.match(r'^([a-z])[\._]?([a-z]{2,})$', local)
        if m:
            return f"{m.group(1).upper()}. {m.group(2).title()}"
        # firstname.lastname
        m = _re.match(r'^([a-z]{2,})[\._]([a-z]{2,})$', local)
        if m:
            return f"{m.group(1).title()} {m.group(2).title()}"
        return ""

    def _usernames_from_name(name: str) -> list:
        parts = name.lower().split()
        if len(parts) < 2:
            return [parts[0]] if parts else []
        first, last = parts[0], parts[-1]
        fi = first[0]
        return [f"{fi}{last}", f"{first}.{last}", f"{first}{last}", f"{first}_{last}"]

    def _stopped():
        return runner.cancelled

    try:
        # ══════════════════════════════════════════════════════════════════════
        # PHASE 1: Direct input recon
        # ══════════════════════════════════════════════════════════════════════

        # ── Username recon ────────────────────────────────────────────────────

        if username and not _stopped() and (tool_group in ("all", "username")):
            q.put({"type": "phase", "msg": f"Username recon — {username}"})
            if not _stopped() and _should_run("sherlock", "username"):     results["sherlock"]     = runner.run_sherlock(username)
            if not _stopped() and _should_run("whatsmyname", "username"):  results["whatsmyname"]  = runner.run_whatsmyname(username)
            if not _stopped() and _should_run("gitfive", "username"):      results["gitfive"]      = runner.run_gitfive(username)

        # ── Email recon ───────────────────────────────────────────────────────

        if email and not _stopped() and (tool_group in ("all", "email")):
            q.put({"type": "phase", "msg": f"Email recon — {email}"})
            if not _stopped() and _should_run("holehe", "email"):   results["holehe"]   = runner.run_holehe(email)
            if not _stopped() and _should_run("ghunt", "email"):    results["ghunt"]    = runner.run_ghunt(email)
            if not _stopped() and _should_run("emailrep", "email"): results["emailrep"] = runner.run_emailrep(email)
            if not _stopped() and _should_run("hibp", "email"):     results["hibp"]     = runner.run_haveibeenpwned(email)

            # Extract name from email if no person_name was given
            guessed = _extract_name_from_email(email)
            if guessed and guessed not in discovered_names:
                q.put({"type": "log", "tool": "chain", "msg": f"Extracted name from email: {guessed}"})
                discovered_names.add(guessed)

        # ── Domain / company recon ────────────────────────────────────────────

        if domain and not _stopped() and (tool_group in ("all", "domain")):
            q.put({"type": "phase", "msg": f"Domain recon — {domain}"})
            if not _stopped() and _should_run("theharvester", "domain"): results["theharvester"] = runner.run_theharvester(domain)
            if not _stopped() and _should_run("subfinder", "domain"):    results["subfinder"]    = runner.run_subfinder(domain)
            if not _stopped() and _should_run("amass", "domain"):        results["amass"]        = runner.run_amass(domain)
            if not _stopped() and _should_run("shodan", "domain"):       results["shodan"]       = runner.run_shodan(domain)
            if not _stopped() and _should_run("censys", "domain"):       results["censys"]       = runner.run_censys(domain)

            if not _stopped() and _should_run("web_scrape", "domain"):
                q.put({"type": "phase", "msg": f"Website scrape — https://{domain}"})
                results["web_scrape"] = runner.run_web_scrape(f"https://{domain}")

            # Collect discovered emails & names from scraper + harvester
            for em in results.get("theharvester", {}).get("emails", []):
                discovered_emails.add(em)
            for em in results.get("web_scrape", {}).get("emails_found", []):
                discovered_emails.add(em)
            for person in results.get("web_scrape", {}).get("people", []):
                pname = person.get("name", "").strip()
                pemail = person.get("email", "").strip()
                if pname:
                    discovered_names.add(pname)
                if pemail:
                    discovered_emails.add(pemail)

            if not _stopped() and _should_run("email_enum", "domain"):
                q.put({"type": "phase", "msg": f"Email enumeration — {domain}"})
                results["email_enum"] = runner.run_email_enum(domain, known_emails=list(discovered_emails))

        # ── Person name recon ──────────────────────────────────────────────

        if person_name and not _stopped() and (tool_group in ("all", "person")):
            q.put({"type": "phase", "msg": f"Person name recon — {person_name}"})
            if not _stopped() and _should_run("maigret", "person"):            results["maigret"]            = runner.run_maigret(person_name)
            if not _stopped() and _should_run("social_analyzer", "person"):    results["social_analyzer"]    = runner.run_social_analyzer(person_name)
            if not _stopped() and _should_run("google_dork_person", "person"): results["google_dork_person"] = runner.run_google_dork(person_name, query_type="person")

            # Collect usernames discovered by maigret
            for acct in results.get("maigret", {}).get("accounts", []):
                un = acct.get("username", "")
                if un:
                    discovered_usernames.add(un)

        # ── Company recon ─────────────────────────────────────────────────

        if company and not _stopped() and (tool_group in ("all", "company")):
            q.put({"type": "phase", "msg": f"Company recon — {company}"})
            if not _stopped() and _should_run("company_search", "company"):     results["company_search"]     = runner.run_company_search(company)
            if not _stopped() and _should_run("google_dork_company", "company"): results["google_dork_company"] = runner.run_google_dork(company, query_type="company")

        # ── GitHub intelligence ───────────────────────────────────────────────

        gh_query = company or person_name
        if gh_query and not _stopped() and _should_run("github", "company"):
            q.put({"type": "phase", "msg": f"GitHub search — {gh_query}"})
            results["github"] = runner.run_github_dork(gh_query)

        # ── Phone lookup ──────────────────────────────────────────────────────

        if phone and not _stopped() and (tool_group in ("all", "phone")):
            q.put({"type": "phase", "msg": f"Phone lookup — {phone}"})
            if not _stopped() and _should_run("phone_lookup", "phone"):
                results["phone_lookup"] = runner.run_phone_lookup(phone)

        # ── Leaked database search ───────────────────────────────────────────

        leak_query = email or domain or username
        if leak_query and not _stopped() and (tool_group in ("all", "domain", "email")):
            if not _stopped() and _should_run("dehashed", "email"):
                q.put({"type": "phase", "msg": f"Leaked DB search — {leak_query}"})
                results["dehashed"] = runner.run_dehashed(leak_query)
            if not _stopped() and _should_run("intelx", "email"):
                results["intelx"] = runner.run_intelx(leak_query)

        # ── WHOIS lookup ─────────────────────────────────────────────────────

        if domain and not _stopped() and _should_run("whois", "domain"):
            results["whois"] = runner.run_whois_lookup(domain)

        # ══════════════════════════════════════════════════════════════════════
        # PHASE 2: Chained recon — run tools on newly discovered intel
        # (only when running all tools)
        # ══════════════════════════════════════════════════════════════════════

        # ── Chain: discovered names → name recon ──────────────────────────

        chain_names = discovered_names - {person_name} if person_name else discovered_names
        if tool_group == "all" and chain_names and not _stopped():
            q.put({"type": "phase", "msg": f"Chained name recon — {len(chain_names)} names discovered"})
            chain_name_results = []
            for nm in list(chain_names)[:5]:
                if _stopped(): break
                q.put({"type": "log", "tool": "chain", "msg": f"Name recon for discovered: {nm}"})
                maigret_r = runner.run_maigret(nm)
                google_r  = runner.run_google_dork(nm, query_type="person")
                for acct in maigret_r.get("accounts", []):
                    un = acct.get("username", "")
                    if un:
                        discovered_usernames.add(un)
                chain_name_results.append({
                    "name": nm,
                    "maigret": maigret_r,
                    "google_dork": google_r,
                })
            results["chain_names"] = chain_name_results

        # ── Chain: discovered emails → email recon ────────────────────────

        chain_emails = discovered_emails - {email} if email else discovered_emails
        chain_emails = {e for e in chain_emails
                        if e.split("@")[0].lower() not in
                        ("info","admin","support","contact","hello","noreply","sales","hr","press","careers","hse")}
        if tool_group == "all" and chain_emails and not _stopped():
            q.put({"type": "phase", "msg": f"Chained email recon — {len(chain_emails)} emails discovered"})
            chain_email_results = []
            for em in list(chain_emails)[:5]:
                if _stopped(): break
                q.put({"type": "log", "tool": "chain", "msg": f"Email recon for discovered: {em}"})
                holehe_r = runner.run_holehe(em)
                hibp_r   = runner.run_haveibeenpwned(em)
                guessed = _extract_name_from_email(em)
                chain_email_results.append({
                    "email": em,
                    "guessed_name": guessed,
                    "holehe": holehe_r,
                    "hibp": hibp_r,
                })
            results["chain_emails"] = chain_email_results

        # ── Chain: discovered usernames → username recon ──────────────────

        chain_usernames = discovered_usernames - {username} if username else discovered_usernames
        if tool_group == "all" and chain_usernames and not _stopped():
            q.put({"type": "phase", "msg": f"Chained username recon — {len(chain_usernames)} usernames discovered"})
            chain_user_results = []
            for un in list(chain_usernames)[:4]:
                if _stopped(): break
                q.put({"type": "log", "tool": "chain", "msg": f"Username recon for discovered: {un}"})
                sherlock_r = runner.run_sherlock(un)
                chain_user_results.append({
                    "username": un,
                    "sherlock": sherlock_r,
                })
            results["chain_usernames"] = chain_user_results

    except Exception as exc:
        q.put({"type": "error", "tool": "orchestrator", "msg": str(exc)})

    # Finalise
    scans[scan_id]["results"].update(results)
    scans[scan_id]["status"]  = "stopped" if _stopped() else "done"
    scans[scan_id]["ended_at"] = time.time()

    # Persist to database
    try:
        db_mod.save_scan(scans[scan_id])
    except Exception:
        pass

    if _stopped():
        q.put({"type": "phase", "msg": "Scan stopped by user"})
    q.put({"type": "done", "results": results})


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
# Face / Reverse image search
# ──────────────────────────────────────────────────────────────────────────────

def _validate_image(file_path: str) -> bool:
    """Validate that a file is a real image and strip any embedded payloads.
    Checks magic bytes + re-encodes via Pillow to sanitize metadata/exploits."""
    _MAGIC = {
        b'\xff\xd8\xff': '.jpg',
        b'\x89PNG':      '.png',
        b'GIF8':         '.gif',
        b'RIFF':         '.webp',
    }

    # 1. Check file size (max 20 MB)
    size = os.path.getsize(file_path)
    if size > 20 * 1024 * 1024:
        return False
    if size < 100:
        return False

    # 2. Verify magic bytes
    with open(file_path, 'rb') as f:
        header = f.read(16)
    valid_magic = any(header.startswith(m) for m in _MAGIC)
    if not valid_magic:
        return False

    # 3. Re-encode through Pillow to strip metadata, embedded scripts, polyglots
    try:
        from PIL import Image
        img = Image.open(file_path)
        img.verify()  # Check for corruption
        # Re-open (verify() exhausts the file) and save clean copy
        img = Image.open(file_path)
        # Convert RGBA to RGB for JPEG
        if img.mode in ('RGBA', 'P'):
            img = img.convert('RGB')
        clean_path = file_path + '.clean.jpg'
        img.save(clean_path, 'JPEG', quality=90)
        os.replace(clean_path, file_path)
        return True
    except ImportError:
        # Pillow not installed — fall back to magic-byte check only
        return valid_magic
    except Exception:
        return False


@app.route("/api/scan/face", methods=["POST"])
def face_scan():
    """Accept image upload or URL and run reverse image search across engines."""
    import tempfile
    scan_id = uuid.uuid4().hex[:10]

    # Handle file upload or URL
    image_path = None
    if "image" in request.files:
        f = request.files["image"]
        # Whitelist allowed extensions
        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'):
            return jsonify({"error": "Invalid file type. Allowed: jpg, png, gif, webp"}), 400
        # Size check (max 20 MB)
        f.seek(0, 2)
        fsize = f.tell()
        f.seek(0)
        if fsize > 20 * 1024 * 1024:
            return jsonify({"error": "Image too large (max 20 MB)"}), 400
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.jpg', dir=tempfile.gettempdir())
        f.save(tmp.name)
        if not _validate_image(tmp.name):
            os.unlink(tmp.name)
            return jsonify({"error": "Invalid or potentially malicious image file"}), 400
        image_path = tmp.name
    elif request.form.get("image_url"):
        image_url = request.form["image_url"].strip()
        # Validate URL scheme
        if not image_url.startswith(('http://', 'https://')):
            return jsonify({"error": "Invalid URL scheme"}), 400
        # Download the image
        try:
            req = urllib.request.Request(image_url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                # Check Content-Type
                ctype = resp.headers.get("Content-Type", "")
                if not any(t in ctype for t in ("image/", "octet-stream")):
                    return jsonify({"error": f"URL does not point to an image (Content-Type: {ctype})"}), 400
                data = resp.read(21 * 1024 * 1024)  # max 20MB + margin
                if len(data) > 20 * 1024 * 1024:
                    return jsonify({"error": "Image too large (max 20 MB)"}), 400
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.jpg', dir=tempfile.gettempdir())
            tmp.write(data)
            tmp.close()
            if not _validate_image(tmp.name):
                os.unlink(tmp.name)
                return jsonify({"error": "Downloaded file is not a valid image"}), 400
            image_path = tmp.name
        except Exception as e:
            return jsonify({"error": f"Failed to download image: {e}"}), 400
    else:
        return jsonify({"error": "No image file or URL provided"}), 400

    scans[scan_id] = {
        "id": scan_id,
        "status": "running",
        "inputs": {"type": "face_search", "image_path": image_path},
        "results": {},
        "logs": [],
        "started_at": time.time(),
    }
    scan_queues[scan_id] = queue.Queue()
    cancel_events[scan_id] = threading.Event()

    thread = threading.Thread(target=_run_face_scan, args=(scan_id, image_path), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id})


def _run_face_scan(scan_id: str, image_path: str):
    q = scan_queues[scan_id]
    ce = cancel_events.get(scan_id)
    runner = ToolRunner(scan_id, q, cancel_event=ce)
    results = {}

    def _stopped():
        return runner.cancelled

    try:
        q.put({"type": "phase", "msg": "Face / Reverse image search"})

        if not _stopped():
            q.put({"type": "log", "tool": "google_images", "msg": "Starting Google Lens reverse image search..."})
            results["google_images"] = runner.run_google_reverse_image(image_path)

        if not _stopped():
            q.put({"type": "log", "tool": "yandex_images", "msg": "Starting Yandex reverse image search..."})
            results["yandex_images"] = runner.run_yandex_reverse_image(image_path)

        if not _stopped():
            q.put({"type": "log", "tool": "bing_images", "msg": "Starting Bing Visual Search..."})
            results["bing_images"] = runner.run_bing_reverse_image(image_path)

        if not _stopped():
            q.put({"type": "log", "tool": "tineye", "msg": "Starting TinEye search..."})
            results["tineye"] = runner.run_tineye(image_path)

        if not _stopped() and os.environ.get("PIMEYES_API_KEY"):
            q.put({"type": "log", "tool": "pimeyes", "msg": "Starting PimEyes search..."})
            results["pimeyes"] = runner.run_pimeyes(image_path)

        if not _stopped() and os.environ.get("FACECHECK_API_KEY"):
            q.put({"type": "log", "tool": "facecheck", "msg": "Starting FaceCheck.ID search..."})
            results["facecheck"] = runner.run_facecheck(image_path)

    except Exception as exc:
        q.put({"type": "error", "tool": "face_search", "msg": str(exc)})

    scans[scan_id]["results"].update(results)
    scans[scan_id]["status"] = "stopped" if _stopped() else "done"
    scans[scan_id]["ended_at"] = time.time()

    try:
        db_mod.save_scan(scans[scan_id])
    except Exception:
        pass

    q.put({"type": "done", "results": results})

    # Cleanup temp file
    try:
        os.unlink(image_path)
    except OSError:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# Email pattern generation
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/email-pattern/generate", methods=["POST"])
def email_pattern_generate():
    """Generate email addresses from names + pattern + domain."""
    data = request.get_json(force=True)
    pattern = data.get("pattern", "john.smith")
    domain  = data.get("domain", "").strip().lstrip("@")
    names   = data.get("names", [])  # list of "First Last" strings

    if not domain:
        return jsonify({"error": "Domain is required"}), 400
    if not names:
        return jsonify({"error": "At least one name is required"}), 400

    from tools import _PATTERN_FORMATS
    fmt_fn = _PATTERN_FORMATS.get(pattern)
    if not fmt_fn:
        return jsonify({"error": f"Unknown pattern: {pattern}"}), 400

    emails = []
    for name in names:
        parts = name.strip().split()
        if len(parts) < 2:
            continue
        first = parts[0].lower()
        last  = parts[-1].lower()
        local = fmt_fn(first, last)
        emails.append(f"{local}@{domain}")

    return jsonify({"emails": emails, "pattern": pattern, "domain": domain, "count": len(emails)})


@app.route("/api/email-pattern/probe", methods=["POST"])
def email_pattern_probe():
    """Probe a domain to detect email naming pattern via O365."""
    data = request.get_json(force=True)
    domain = data.get("domain", "").strip().lstrip("@")
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    from tools import _probe_pattern
    pattern = _probe_pattern(domain)
    return jsonify({"domain": domain, "pattern": pattern})


# ──────────────────────────────────────────────────────────────────────────────
# Centralised API key management
# ──────────────────────────────────────────────────────────────────────────────

_ALL_KEYS = [
    # OSINT tools
    {"id": "HIBP_API_KEY",        "label": "HaveIBeenPwned",   "group": "OSINT Tools",  "hint": "haveibeenpwned.com/API/Key"},
    {"id": "SHODAN_API_KEY",      "label": "Shodan",           "group": "OSINT Tools",  "hint": "shodan.io"},
    {"id": "CENSYS_API_ID",       "label": "Censys API ID",    "group": "OSINT Tools",  "hint": "censys.io"},
    {"id": "CENSYS_API_SECRET",   "label": "Censys API Secret","group": "OSINT Tools",  "hint": "censys.io"},
    {"id": "EMAILREP_KEY",        "label": "EmailRep",         "group": "OSINT Tools",  "hint": "emailrep.io"},
    # AI
    {"id": "ANTHROPIC_API_KEY",   "label": "Anthropic (Claude)","group": "AI",          "hint": "console.anthropic.com"},
    {"id": "OPENAI_API_KEY",      "label": "OpenAI",            "group": "AI",          "hint": "platform.openai.com"},
    # Phishing / GoPhish
    {"id": "GOPHISH_API_KEY",     "label": "GoPhish API Key",   "group": "Phishing",    "hint": "From gophish.db"},
    # Vishing
    {"id": "TWILIO_ACCOUNT_SID",  "label": "Twilio Account SID","group": "Vishing",     "hint": "twilio.com/console"},
    {"id": "TWILIO_AUTH_TOKEN",   "label": "Twilio Auth Token", "group": "Vishing",     "hint": "twilio.com/console"},
    {"id": "TWILIO_CALLER_ID",    "label": "Twilio Caller ID",  "group": "Vishing",     "hint": "Phone number"},
    {"id": "ELEVENLABS_API_KEY",  "label": "ElevenLabs",        "group": "Vishing",     "hint": "elevenlabs.io"},
    {"id": "ELEVENLABS_VOICE_ID", "label": "ElevenLabs Voice",  "group": "Vishing",     "hint": "Voice ID string"},
    # Face / Image search (paid)
    {"id": "TINEYE_API_KEY",      "label": "TinEye",            "group": "Face Search", "hint": "tineye.com/developer"},
    {"id": "PIMEYES_API_KEY",     "label": "PimEyes",           "group": "Face Search", "hint": "pimeyes.com (paid)"},
    {"id": "FACECHECK_API_KEY",   "label": "FaceCheck.ID",      "group": "Face Search", "hint": "facecheck.id (paid)"},
    # Phone lookup
    {"id": "NUMVERIFY_API_KEY",   "label": "NumVerify",         "group": "Phone",       "hint": "numverify.com"},
    {"id": "ABSTRACT_API_KEY",    "label": "Abstract API",      "group": "Phone",       "hint": "abstractapi.com"},
    # Leaked databases
    {"id": "DEHASHED_API_KEY",    "label": "Dehashed",          "group": "Leaked DB",   "hint": "dehashed.com"},
    {"id": "INTELX_API_KEY",     "label": "IntelligenceX",     "group": "Leaked DB",   "hint": "intelx.io"},
    # IP lookup
    {"id": "IPINFO_TOKEN",       "label": "IPInfo",            "group": "OSINT Tools", "hint": "ipinfo.io"},
    # Social media
    {"id": "PROXYCURL_API_KEY",  "label": "Proxycurl (LinkedIn)","group": "OSINT Tools","hint": "proxycurl.com"},
]


@app.route("/api/config/keys", methods=["GET"])
def config_keys_status():
    """Return configured/missing status for every known API key (never returns actual values)."""
    result = []
    for k in _ALL_KEYS:
        val = os.environ.get(k["id"], "")
        # GoPhish key may live in the gophish module
        if k["id"] == "GOPHISH_API_KEY" and not val:
            val = getattr(gophish, "API_KEY", "") or ""
        result.append({
            "id": k["id"],
            "label": k["label"],
            "group": k["group"],
            "hint": k["hint"],
            "configured": bool(val),
        })
    return jsonify(result)


@app.route("/api/config/keys", methods=["POST"])
def config_keys_save():
    """Set one or more API keys and persist to database."""
    data = request.get_json(force=True)
    updated = []
    for k in _ALL_KEYS:
        val = data.get(k["id"], "").strip()
        if val:
            if k["id"] == "GOPHISH_API_KEY":
                gophish.set_key(val)
            else:
                os.environ[k["id"]] = val
            db_mod.save_api_key(k["id"], val)
            updated.append(k["id"])
    return jsonify({"ok": True, "updated": updated})


# ──────────────────────────────────────────────────────────────────────────────
# Export endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/scans/<scan_id>/export")
def export_scan(scan_id):
    """Export scan results as JSON or CSV."""
    fmt = request.args.get("format", "json")
    scan = scans.get(scan_id) or db_mod.get_scan(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if fmt == "csv":
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Tool", "Key", "Value"])
        for tool, data in scan.get("results", {}).items():
            if isinstance(data, dict):
                for k, v in data.items():
                    writer.writerow([tool, k, json.dumps(v) if isinstance(v, (list, dict)) else str(v)])
        resp = Response(output.getvalue(), mimetype="text/csv")
        resp.headers["Content-Disposition"] = f'attachment; filename="scan_{scan_id}.csv"'
        return resp

    # Default: JSON
    resp = Response(json.dumps(scan, indent=2, default=str), mimetype="application/json")
    resp.headers["Content-Disposition"] = f'attachment; filename="scan_{scan_id}.json"'
    return resp


@app.route("/api/vishing/campaigns/<camp_id>/export")
def export_campaign(camp_id):
    """Export vishing campaign with call logs as JSON."""
    camp = vishing_campaigns.get(camp_id) or db_mod.get_campaign(camp_id)
    if not camp:
        return jsonify({"error": "Campaign not found"}), 404
    resp = Response(json.dumps(camp, indent=2, default=str), mimetype="application/json")
    resp.headers["Content-Disposition"] = f'attachment; filename="campaign_{camp_id}.json"'
    return resp


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5000)))
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument("--smtp-port", type=int, default=int(os.environ.get("SMTP_RELAY_PORT", 2525)))
    parser.add_argument("--domain", default=os.environ.get("MAIL_DOMAIN", "example.com"))
    parser.add_argument("--no-smtp", action="store_true", help="Don't start local SMTP relay")
    args = parser.parse_args()

    # ── Auto-configure SMTP ──────────────────────────────────────────────
    # Priority: env vars → local relay fallback
    _smtp_host = os.environ.get("SMTP_HOST", "")
    _smtp_port = int(os.environ.get("SMTP_PORT", "587"))
    _smtp_user = os.environ.get("SMTP_USER", "")
    _smtp_pass = os.environ.get("SMTP_PASS", "")
    _smtp_tls  = os.environ.get("SMTP_TLS", "false").lower() == "true"

    if _smtp_host and _smtp_user and _smtp_pass:
        # Use configured/default Aruba SMTP
        mailer.save_config({
            "host": _smtp_host,
            "port": _smtp_port,
            "user": _smtp_user,
            "password": _smtp_pass,
            "use_tls": _smtp_tls,
        })
        print(f"[*] SMTP configured: {_smtp_user} via {_smtp_host}:{_smtp_port}")
    elif not args.no_smtp:
        # Fallback: start local SMTP relay
        smtp_port = local_smtp.start(port=args.smtp_port, domain=args.domain)
        mailer.save_config({
            "host": "127.0.0.1",
            "port": smtp_port,
            "user": f"relay@{args.domain}",
            "password": "local",
            "use_tls": False,
        })
        print(f"[*] Local SMTP relay on 127.0.0.1:{smtp_port} (domain: {args.domain})")

    # ── Auto-configure GoPhish SMTP sending profile ────────────────────
    if _smtp_host and _smtp_user and _smtp_pass:
        gp = gophish.ping()
        if gp.get("ok"):
            existing = gophish.list_smtp()
            profile_name = "RedBalance Auto"
            already = any(s.get("name") == profile_name for s in existing) if isinstance(existing, list) else False
            if not already:
                result = gophish.create_smtp(
                    name=profile_name,
                    host=_smtp_host,
                    port=_smtp_port,
                    username=_smtp_user,
                    password=_smtp_pass,
                    from_address=_smtp_user,
                    use_tls=not _smtp_tls,  # Aruba 465 = SSL, not STARTTLS
                )
                if result.get("id"):
                    print(f"[*] GoPhish SMTP profile created: '{profile_name}' ({_smtp_user})")
                else:
                    print(f"[!] GoPhish SMTP profile creation failed: {result}")
            else:
                print(f"[*] GoPhish SMTP profile '{profile_name}' already exists")
        else:
            print(f"[!] GoPhish not reachable — SMTP profile not created")

    print(f"[*] Starting OSINT Dashboard on {args.host}:{args.port}")
    app.run(debug=False, threaded=True, host=args.host, port=args.port)
