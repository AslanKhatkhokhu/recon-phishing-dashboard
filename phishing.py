"""
Phishing Email Generator — RedBalance Red Team Platform
FOR AUTHORIZED PENETRATION TESTING ENGAGEMENTS ONLY.

Generates personalized phishing email templates based on OSINT scan results.
Each template is contextualised using target name, position, company, domain,
and infrastructure data gathered during the recon phase.
"""

import re
from datetime import date


# ──────────────────────────────────────────────────────────────────────────────
# Target context builder
# ──────────────────────────────────────────────────────────────────────────────

def build_context(scan: dict) -> dict:
    """
    Extract relevant fields from a finished scan record and return a flat
    context dict that templates can reference.
    """
    inputs   = scan.get("inputs", {})
    results  = scan.get("results", {})

    person_name  = inputs.get("person_name", "").strip()
    email        = inputs.get("email", "").strip()
    company      = inputs.get("company", "").strip()
    domain       = inputs.get("domain", "").strip()
    username     = inputs.get("username", "").strip()

    # ── Name parts ──────────────────────────────────────────────────────────
    first_name = last_name = full_name = ""
    if person_name:
        parts = person_name.strip().split()
        first_name = parts[0].capitalize() if parts else ""
        last_name  = parts[-1].capitalize() if len(parts) > 1 else ""
        full_name  = person_name.strip().title()
    elif email:
        local = email.split("@")[0]
        # Try to parse j.smith or john.smith patterns
        if "." in local:
            p = local.split(".")
            first_name = p[0].capitalize()
            last_name  = p[-1].capitalize()
        else:
            first_name = local.capitalize()
        full_name = f"{first_name} {last_name}".strip()

    # ── Position / title ────────────────────────────────────────────────────
    position = ""
    github_data = results.get("github", {})
    for user in github_data.get("users", []):
        if user.get("name") or user.get("login"):
            position = user.get("bio", "") or ""
            if not full_name and user.get("name"):
                full_name = user["name"]
            break

    # ── Company / domain ────────────────────────────────────────────────────
    if not company and domain:
        # Derive company name from domain root (e.g. technikum-wien.at → Technikum Wien)
        root = domain.split(".")[0].replace("-", " ").title()
        company = root

    # ── Infrastructure hints (from subdomains) ───────────────────────────────
    all_hosts = []
    for src in ("theharvester", "subfinder", "amass"):
        r = results.get(src, {})
        all_hosts += [s if isinstance(s, str) else s.get("host", "") for s in r.get("subdomains", [])]
        all_hosts += r.get("hosts", [])

    has_vpn      = any("vpn"       in h for h in all_hosts)
    has_mail     = any(re.match(r"(mail|smtp|imap|autodiscover)\.", h) for h in all_hosts)
    has_moodle   = any("moodle"    in h for h in all_hosts)
    has_sso      = any(re.match(r"(sso|idp|saml|auth|login)\.", h) for h in all_hosts)
    has_cloud    = any("cloud"     in h for h in all_hosts)
    has_git      = any(re.match(r"(git|gitlab|github)\.", h) for h in all_hosts)
    has_helpdesk = any(re.match(r"(otobo|otrs|helpdesk|support|ticket)\.", h) for h in all_hosts)

    # ── Confirmed valid emails from enumeration ──────────────────────────────
    valid_emails = results.get("email_enum", {}).get("valid", [])

    # ── Breach context ───────────────────────────────────────────────────────
    breach_names = [b["name"] for b in results.get("hibp", {}).get("breaches", [])]

    return {
        "first_name":   first_name or "User",
        "last_name":    last_name,
        "full_name":    full_name or first_name or "User",
        "email":        email,
        "username":     username,
        "company":      company or domain or "your organisation",
        "domain":       domain or (email.split("@")[1] if "@" in email else ""),
        "position":     position,
        "has_vpn":      has_vpn,
        "has_mail":     has_mail,
        "has_moodle":   has_moodle,
        "has_sso":      has_sso,
        "has_cloud":    has_cloud,
        "has_git":      has_git,
        "has_helpdesk": has_helpdesk,
        "valid_emails": valid_emails,
        "breaches":     breach_names,
        "today":        date.today().strftime("%d %B %Y"),
        "year":         date.today().year,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Template definitions
# ──────────────────────────────────────────────────────────────────────────────

TEMPLATES = {}

def _register(key, label, description, icon):
    def decorator(fn):
        TEMPLATES[key] = {
            "key":         key,
            "label":       label,
            "description": description,
            "icon":        icon,
            "fn":          fn,
        }
        return fn
    return decorator


# ── 1. Credential / Password Reset ──────────────────────────────────────────

@_register("credential_reset", "Credential Reset", "IT password expiry / forced reset", "bi-key")
def tpl_credential_reset(ctx: dict) -> dict:
    domain    = ctx["domain"]
    company   = ctx["company"]
    first     = ctx["first_name"]
    login_url = "https://example.com/login/index.php"

    subject = f"[ACTION REQUIRED] Your {company} password expires today"

    body_html = f"""
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#222">
  <div style="background:#c00;padding:12px 20px;">
    <span style="color:#fff;font-weight:bold;font-size:16px">{company} IT Security</span>
  </div>
  <div style="padding:24px 20px;border:1px solid #ddd;border-top:none">
    <p>Dear {first},</p>
    <p>Our systems have detected that your <strong>{company} network password will expire in less than 24 hours</strong>.
    To avoid losing access to your email, VPN and internal services, please reset your password immediately.</p>
    <p style="text-align:center;margin:30px 0">
      <a href="{login_url}" style="background:#c00;color:#fff;padding:12px 28px;text-decoration:none;border-radius:4px;font-weight:bold">
        Reset My Password Now
      </a>
    </p>
    <p>If you do not reset your password within the next <strong>4 hours</strong>, your account will be
    temporarily suspended and you will need to contact the helpdesk to regain access.</p>
    <hr style="border:none;border-top:1px solid #eee;margin:24px 0">
    <p style="font-size:12px;color:#888">
      {company} IT Helpdesk &nbsp;|&nbsp; helpdesk@{domain}<br>
      This is an automated message. Please do not reply directly to this email.<br>
      &copy; {ctx["year"]} {company}
    </p>
  </div>
</div>"""

    body_text = f"""Dear {first},

Our systems have detected that your {company} network password will expire in less than 24 hours.

To avoid losing access to your email, VPN and internal services, please reset your password immediately:

  {login_url}

If you do not reset your password within the next 4 hours, your account will be temporarily suspended.

{company} IT Helpdesk | helpdesk@{domain}"""

    notes = [
        f"Sender: helpdesk@{domain} or it-support@{domain}",
        "Urgency + account suspension threat drives fast clicks",
        f"Reset URL should point to your credential harvester (replace {login_url})",
    ]
    if ctx["has_vpn"]:
        notes.append("Target has a VPN subdomain — mention VPN access loss for extra pressure")
    if ctx["breaches"]:
        notes.append(f"Target has been in breaches ({', '.join(ctx['breaches'][:3])}) — may reuse passwords")

    return {"subject": subject, "body_html": body_html, "body_text": body_text, "notes": notes,
            "from_suggestion": f"helpdesk@{domain}", "pretext": "Password expiry urgency"}


# ── 2. IT Helpdesk Ticket ─────────────────────────────────────────────────────

@_register("it_helpdesk", "IT Helpdesk Ticket", "Support ticket requiring user action", "bi-headset")
def tpl_it_helpdesk(ctx: dict) -> dict:
    domain  = ctx["domain"]
    company = ctx["company"]
    first   = ctx["first_name"]
    ticket  = f"TKT-{hash(ctx['email'] or first) % 90000 + 10000}"
    link    = "https://example.com/login/index.php"

    subject = f"[{ticket}] Action required — security audit on your workstation"

    body_html = f"""
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#222">
  <div style="background:#1a73e8;padding:12px 20px;">
    <span style="color:#fff;font-weight:bold">{company} Service Desk</span>
    <span style="color:#aad4f5;float:right;font-size:13px">Ticket {ticket}</span>
  </div>
  <div style="padding:24px 20px;border:1px solid #ddd;border-top:none">
    <p>Hi {first},</p>
    <p>A routine security audit has flagged your workstation for an <strong>agent update</strong>.
    This update patches a critical vulnerability (CVE-2024-38112) identified in our endpoint protection software.</p>
    <p>Please click the link below to <strong>authorise the remote update</strong> and keep your machine compliant:</p>
    <p style="text-align:center;margin:28px 0">
      <a href="{link}" style="background:#1a73e8;color:#fff;padding:11px 26px;text-decoration:none;border-radius:4px;font-weight:bold">
        Authorise Update &rarr;
      </a>
    </p>
    <p>The update takes approximately 3 minutes. You may be asked to log in with your {company} credentials to verify your identity.</p>
    <p style="font-size:12px;color:#888;margin-top:24px">
      {company} Service Desk &nbsp;&bull;&nbsp; helpdesk@{domain}<br>
      Ticket {ticket} &nbsp;&bull;&nbsp; Opened {ctx["today"]}
    </p>
  </div>
</div>"""

    body_text = f"""Hi {first},

A routine security audit has flagged your workstation for an agent update.

Ticket: {ticket}

Please click the link below to authorise the remote update:
{link}

The update takes approximately 3 minutes. You may be asked to log in with your {company}
credentials to verify your identity.

{company} Service Desk | helpdesk@{domain}"""

    notes = [
        f"Sender: helpdesk@{domain} or servicedesk@{domain}",
        "CVE reference adds technical credibility",
        f"Replace {link} with your payload URL",
        "Credential prompt during 'update' captures creds",
    ]
    if ctx["has_helpdesk"]:
        notes.insert(0, f"Target runs a real helpdesk system at helpdesk.{domain} — spoof its branding")

    return {"subject": subject, "body_html": body_html, "body_text": body_text, "notes": notes,
            "from_suggestion": f"helpdesk@{domain}", "pretext": "Patch compliance / CVE urgency"}


# ── 3. CEO / Executive Fraud ─────────────────────────────────────────────────

@_register("ceo_fraud", "CEO / Executive Fraud", "Urgent request impersonating a senior executive", "bi-person-badge")
def tpl_ceo_fraud(ctx: dict) -> dict:
    domain  = ctx["domain"]
    company = ctx["company"]
    first   = ctx["first_name"]
    position = ctx["position"] or "colleague"

    subject = f"Urgent — confidential request from the CEO"

    body_html = f"""
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#222">
  <div style="padding:24px 20px;border:1px solid #ddd">
    <p>Hi {first},</p>
    <p>I hope this finds you well. I'm currently in a board meeting and cannot take calls.</p>
    <p>I need you to handle something <strong>confidential and time-sensitive</strong> for me right now.
    We are finalising an acquisition and I need a vendor invoice processed before close of business today.
    The finance team cannot be involved at this stage for confidentiality reasons.</p>
    <p>Can you confirm you are available? Reply to this email only — do <strong>not</strong> discuss
    this with anyone else until the deal is announced.</p>
    <p>Best regards,<br>
    <strong>[CEO Name]</strong><br>
    Chief Executive Officer, {company}</p>
    <p style="font-size:11px;color:#aaa">Sent from iPhone</p>
  </div>
</div>"""

    body_text = f"""Hi {first},

I hope this finds you well. I'm currently in a board meeting and cannot take calls.

I need you to handle something confidential and time-sensitive for me right now.
We are finalising an acquisition and I need a vendor invoice processed before close of business today.
The finance team cannot be involved at this stage for confidentiality reasons.

Can you confirm you are available? Reply to this email only — do not discuss this with anyone else.

Best regards,
[CEO Name]
Chief Executive Officer, {company}

Sent from iPhone"""

    notes = [
        f"Sender: use a lookalike domain (e.g. {domain.replace('.', '-ceo.')} or {domain.replace('.at', '.co')})",
        "Do NOT send from the real domain — reply-to should differ from from-address",
        f"Research the real CEO name on LinkedIn / {company} website before sending",
        "Target's position: " + (ctx["position"] or "unknown — research before sending"),
        "Follow-up with a fake invoice PDF containing a macro or link",
    ]
    if ctx["breaches"]:
        notes.append(f"Target appeared in {', '.join(ctx['breaches'][:2])} — may be less security-aware")

    return {"subject": subject, "body_html": body_html, "body_text": body_text, "notes": notes,
            "from_suggestion": f"ceo@{domain.split('.')[0]}-group.com (lookalike)", "pretext": "BEC / wire fraud pretext"}


# ── 4. Document Share (OneDrive / SharePoint) ────────────────────────────────

@_register("document_share", "Document Share", "OneDrive / SharePoint file share notification", "bi-file-earmark-text")
def tpl_document_share(ctx: dict) -> dict:
    domain  = ctx["domain"]
    company = ctx["company"]
    first   = ctx["first_name"]
    link    = "https://example.com/login/index.php"

    subject = f"{first}, a document has been shared with you"

    body_html = f"""
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#222">
  <div style="background:#0078d4;padding:14px 20px;display:flex;align-items:center;gap:10px">
    <span style="color:#fff;font-size:22px">&#9744;</span>
    <span style="color:#fff;font-weight:bold;font-size:15px">Microsoft SharePoint</span>
  </div>
  <div style="padding:24px 20px;border:1px solid #ddd;border-top:none">
    <p style="color:#555">HR Department shared a file with you</p>
    <div style="border:1px solid #e0e0e0;border-radius:4px;padding:16px;margin:16px 0;display:flex;align-items:center;gap:14px">
      <span style="font-size:36px">&#128196;</span>
      <div>
        <div style="font-weight:bold">HR_Policy_Update_{ctx["year"]}.pdf</div>
        <div style="font-size:12px;color:#888">Shared by HR Department &bull; {ctx["today"]}</div>
      </div>
    </div>
    <p style="text-align:center;margin:24px 0">
      <a href="{link}" style="background:#0078d4;color:#fff;padding:11px 26px;text-decoration:none;border-radius:4px;font-weight:bold">
        Open in SharePoint
      </a>
    </p>
    <p style="font-size:12px;color:#888">
      You're receiving this because HR Department ({company}) shared a file with you.<br>
      <a href="#" style="color:#0078d4">Unsubscribe</a> &nbsp;&bull;&nbsp;
      <a href="#" style="color:#0078d4">Privacy Statement</a>
    </p>
  </div>
</div>"""

    body_text = f"""HR Department shared a file with you.

File: HR_Policy_Update_{ctx["year"]}.pdf
Shared by: HR Department · {ctx["today"]}

Open the document:
{link}

You're receiving this because HR Department ({company}) shared a file with you."""

    notes = [
        f"Sender: no-reply@sharepointonline.com (spoof Microsoft sender) or noreply@{domain}",
        "HR policy docs have high open rates — staff feel obligated to read them",
        f"Replace {link} with a credential harvester mimicking Microsoft login",
        "Use HTTPS and a convincing domain for the harvester (e.g. sharepoint-{domain.split('.')[0]}.com)",
    ]
    if ctx["has_moodle"]:
        notes.append(f"Target uses Moodle at moodle.{domain} — also effective to spoof a Moodle assignment notification")

    return {"subject": subject, "body_html": body_html, "body_text": body_text, "notes": notes,
            "from_suggestion": "no-reply@sharepointonline.com (spoofed)", "pretext": "HR policy / file share"}


# ── 5. Security Alert ────────────────────────────────────────────────────────

@_register("security_alert", "Security Alert", "Suspicious login / account compromise warning", "bi-shield-exclamation")
def tpl_security_alert(ctx: dict) -> dict:
    domain  = ctx["domain"]
    company = ctx["company"]
    first   = ctx["first_name"]
    link    = "https://example.com/login/index.php"

    subject = f"[{company} Security] Suspicious sign-in detected on your account"

    body_html = f"""
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#222">
  <div style="background:#d93025;padding:12px 20px;">
    <span style="color:#fff;font-weight:bold">&#9888; {company} Security Alert</span>
  </div>
  <div style="padding:24px 20px;border:1px solid #ddd;border-top:none">
    <p>Dear {first},</p>
    <p>We detected a sign-in attempt to your account from an <strong>unrecognised device and location</strong>:</p>
    <table style="width:100%;border-collapse:collapse;margin:16px 0;font-size:13px">
      <tr style="background:#f8f8f8"><td style="padding:8px 10px;border:1px solid #e0e0e0;color:#555">Location</td><td style="padding:8px 10px;border:1px solid #e0e0e0">Romania · Bucharest</td></tr>
      <tr><td style="padding:8px 10px;border:1px solid #e0e0e0;color:#555">Device</td><td style="padding:8px 10px;border:1px solid #e0e0e0">Windows 11 · Chrome 124</td></tr>
      <tr style="background:#f8f8f8"><td style="padding:8px 10px;border:1px solid #e0e0e0;color:#555">Time</td><td style="padding:8px 10px;border:1px solid #e0e0e0">{ctx["today"]} at 03:47 AM (CET)</td></tr>
      <tr><td style="padding:8px 10px;border:1px solid #e0e0e0;color:#555">Status</td><td style="padding:8px 10px;border:1px solid #e0e0e0;color:#d93025;font-weight:bold">Blocked (suspicious)</td></tr>
    </table>
    <p>If this was <strong>not you</strong>, your account may be compromised. Secure it immediately:</p>
    <p style="text-align:center;margin:24px 0">
      <a href="{link}" style="background:#d93025;color:#fff;padding:12px 26px;text-decoration:none;border-radius:4px;font-weight:bold">
        Secure My Account Now
      </a>
    </p>
    <p>If this was you, you can safely ignore this message.</p>
    <hr style="border:none;border-top:1px solid #eee;margin:20px 0">
    <p style="font-size:12px;color:#888">{company} Security Team &nbsp;|&nbsp; security@{domain}<br>&copy; {ctx["year"]} {company}</p>
  </div>
</div>"""

    body_text = f"""Dear {first},

We detected a sign-in attempt to your account from an unrecognised device and location:

  Location : Romania · Bucharest
  Device   : Windows 11 · Chrome 124
  Time     : {ctx["today"]} at 03:47 AM (CET)
  Status   : BLOCKED (suspicious)

If this was not you, your account may be compromised. Secure it immediately:
{link}

{company} Security Team | security@{domain}"""

    notes = [
        f"Sender: security@{domain} or noreply-security@{domain}",
        "Foreign location (Romania/Nigeria/China) maximises fear response",
        f"Replace {link} with your credential harvester",
        "Works especially well on targets with breach history",
    ]
    if ctx["breaches"]:
        notes.insert(0, f"STRONG PRETEXT: Target was in {len(ctx['breaches'])} breach(es) ({', '.join(ctx['breaches'][:3])}) — they're primed to believe their account is at risk")
    if ctx["has_sso"]:
        notes.append(f"Target uses SSO at idp.{domain} — clone that login page for maximum realism")

    return {"subject": subject, "body_html": body_html, "body_text": body_text, "notes": notes,
            "from_suggestion": f"security@{domain}", "pretext": "Account takeover fear / urgency"}


# ── 6. VPN Access Notification ───────────────────────────────────────────────

@_register("vpn_access", "VPN Access Required", "Mandatory VPN client upgrade / re-enrollment", "bi-shield-lock")
def tpl_vpn_access(ctx: dict) -> dict:
    domain  = ctx["domain"]
    company = ctx["company"]
    first   = ctx["first_name"]
    link    = "https://example.com/login/index.php"

    subject = f"[URGENT] {company} VPN client end-of-life — action required by Friday"

    body_html = f"""
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#222">
  <div style="background:#2d6a4f;padding:12px 20px;">
    <span style="color:#fff;font-weight:bold">&#128274; {company} Network Operations</span>
  </div>
  <div style="padding:24px 20px;border:1px solid #ddd;border-top:none">
    <p>Dear {first},</p>
    <p>Our records show you are using an <strong>end-of-life version of the {company} VPN client</strong>
    (Cisco AnyConnect 4.x). Support for this version ends on <strong>Friday</strong>, after which
    remote access will be blocked until you upgrade.</p>
    <p>Please download and install the new client before then:</p>
    <p style="text-align:center;margin:24px 0">
      <a href="{link}" style="background:#2d6a4f;color:#fff;padding:12px 26px;text-decoration:none;border-radius:4px;font-weight:bold">
        Download New VPN Client
      </a>
    </p>
    <p>After installation you will be prompted to re-authenticate with your {company} credentials.
    If you need assistance, contact the IT helpdesk.</p>
    <hr style="border:none;border-top:1px solid #eee;margin:20px 0">
    <p style="font-size:12px;color:#888">{company} Network Operations &nbsp;|&nbsp; netops@{domain}<br>&copy; {ctx["year"]} {company}</p>
  </div>
</div>"""

    body_text = f"""Dear {first},

Our records show you are using an end-of-life version of the {company} VPN client (Cisco AnyConnect 4.x).
Support ends on Friday — after which remote access will be blocked until you upgrade.

Download the new client:
{link}

After installation you will be prompted to re-authenticate with your {company} credentials.

{company} Network Operations | netops@{domain}"""

    notes = [
        f"Sender: netops@{domain} or it-security@{domain}",
        "VPN installer payload = ideal delivery vehicle for initial access",
        f"Replace {link} with a trojanised installer or credential harvester",
        "Deadline pressure ('blocked on Friday') increases urgency",
    ]
    if not ctx["has_vpn"]:
        notes.insert(0, "WARNING: No VPN subdomain detected for this domain — verify target uses VPN before sending")

    return {"subject": subject, "body_html": body_html, "body_text": body_text, "notes": notes,
            "from_suggestion": f"netops@{domain}", "pretext": "VPN EOL / access loss threat"}


# ── 7. Moodle / LMS Notification ─────────────────────────────────────────────

@_register("lms_assignment", "LMS Assignment Due", "Moodle / learning platform assignment deadline", "bi-mortarboard")
def tpl_lms_assignment(ctx: dict) -> dict:
    domain  = ctx["domain"]
    company = ctx["company"]
    first   = ctx["first_name"]
    link    = "https://example.com/login/index.php"

    subject = f"Reminder: mandatory compliance training due tomorrow"

    body_html = f"""
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#222">
  <div style="background:#f98012;padding:12px 20px;">
    <span style="color:#fff;font-weight:bold">&#127891; {company} Learning Platform</span>
  </div>
  <div style="padding:24px 20px;border:1px solid #ddd;border-top:none">
    <p>Dear {first},</p>
    <p>This is a reminder that you have an <strong>incomplete mandatory assignment</strong> due tomorrow:</p>
    <div style="border-left:4px solid #f98012;padding:12px 16px;margin:16px 0;background:#fff8f0">
      <strong>Information Security Awareness 2{ctx["year"] % 100} — Module 3</strong><br>
      <span style="color:#888;font-size:13px">Due: tomorrow &nbsp;&bull;&nbsp; Non-completion may affect your employment record</span>
    </div>
    <p style="text-align:center;margin:24px 0">
      <a href="{link}" style="background:#f98012;color:#fff;padding:12px 26px;text-decoration:none;border-radius:4px;font-weight:bold">
        Complete Assignment
      </a>
    </p>
    <p style="font-size:12px;color:#888">{company} Learning &amp; Development &nbsp;|&nbsp; elearning@{domain}<br>&copy; {ctx["year"]} {company}</p>
  </div>
</div>"""

    body_text = f"""Dear {first},

You have an incomplete mandatory assignment due tomorrow:

  Information Security Awareness 2{ctx["year"] % 100} — Module 3
  Due: tomorrow | Non-completion may affect your employment record

Complete it here:
{link}

{company} Learning & Development | elearning@{domain}"""

    notes = [
        f"Sender: elearning@{domain} or lms@{domain}",
        "Mandatory + employment consequences = high click rate",
        "Irony: security awareness training pretext for phishing",
        f"Replace {link} with harvester after cloning Moodle login page",
    ]
    if not ctx["has_moodle"]:
        notes.insert(0, f"NOTE: No Moodle subdomain detected — verify target uses an LMS before sending")

    return {"subject": subject, "body_html": body_html, "body_text": body_text, "notes": notes,
            "from_suggestion": f"elearning@{domain}", "pretext": "Mandatory training / compliance fear"}


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def list_templates() -> list[dict]:
    return [
        {"key": k, "label": v["label"], "description": v["description"], "icon": v["icon"]}
        for k, v in TEMPLATES.items()
    ]


def generate(scan: dict, template_key: str) -> dict:
    """
    Generate a phishing email from a scan record using the specified template.
    Returns dict with: subject, body_html, body_text, notes, from_suggestion, pretext, context
    """
    if template_key not in TEMPLATES:
        return {"error": f"Unknown template: {template_key}"}

    ctx    = build_context(scan)
    result = TEMPLATES[template_key]["fn"](ctx)
    result["context"] = {k: v for k, v in ctx.items() if not isinstance(v, list) or k == "breaches"}
    result["template"] = template_key
    return result
