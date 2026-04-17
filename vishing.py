"""
Vishing (Voice Phishing) Script Generator — RedBalance Red Team Platform
FOR AUTHORIZED PENETRATION TESTING ENGAGEMENTS ONLY.

Generates contextual call scripts based on OSINT scan results.
"""

import re
from datetime import date


def build_context(scan: dict) -> dict:
    """Extract relevant fields from a scan record for script personalisation."""
    inputs  = scan.get("inputs", {})
    results = scan.get("results", {})

    person_name = inputs.get("person_name", "").strip()
    email       = inputs.get("email", "").strip()
    company     = inputs.get("company", "").strip()
    domain      = inputs.get("domain", "").strip()

    # Name
    first_name = last_name = full_name = ""
    if person_name:
        parts = person_name.strip().split()
        first_name = parts[0].capitalize() if parts else ""
        last_name  = parts[-1].capitalize() if len(parts) > 1 else ""
        full_name  = person_name.strip().title()
    elif email:
        local = email.split("@")[0]
        if "." in local:
            p = local.split(".")
            first_name = p[0].capitalize()
            last_name  = p[-1].capitalize()
        else:
            first_name = local.capitalize()
        full_name = f"{first_name} {last_name}".strip()

    # Company
    if not company and domain:
        root = domain.split(".")[0].replace("-", " ").title()
        company = root

    # Infrastructure
    all_hosts = []
    for src in ("theharvester", "subfinder", "amass"):
        r = results.get(src, {})
        all_hosts += [s if isinstance(s, str) else s.get("host", "") for s in r.get("subdomains", [])]
        all_hosts += r.get("hosts", [])

    has_vpn      = any("vpn" in h for h in all_hosts)
    has_helpdesk = any(re.match(r"(otobo|otrs|helpdesk|support|ticket)\.", h) for h in all_hosts)
    has_sso      = any(re.match(r"(sso|idp|saml|auth|login)\.", h) for h in all_hosts)

    # Position from GitHub
    position = ""
    for user in results.get("github", {}).get("users", []):
        if user.get("bio"):
            position = user["bio"]
            break

    breach_names = [b["name"] for b in results.get("hibp", {}).get("breaches", [])]

    return {
        "first_name":   first_name or "there",
        "last_name":    last_name,
        "full_name":    full_name or first_name or "Target",
        "email":        email,
        "company":      company or "your organisation",
        "domain":       domain or (email.split("@")[1] if "@" in email else ""),
        "position":     position,
        "has_vpn":      has_vpn,
        "has_helpdesk": has_helpdesk,
        "has_sso":      has_sso,
        "breaches":     breach_names,
        "today":        date.today().strftime("%d %B %Y"),
        "year":         date.today().year,
    }


SCRIPTS: dict = {}


def _register(key, label, description, icon):
    def decorator(fn):
        SCRIPTS[key] = {
            "key": key, "label": label,
            "description": description, "icon": icon, "fn": fn,
        }
        return fn
    return decorator


# ── 1. IT Support — Account Security Check ───────────────────────────────────

@_register("it_support", "IT Support", "IT department calling about a security alert on the target's account", "bi-headset")
def script_it_support(ctx: dict) -> dict:
    first   = ctx["first_name"]
    company = ctx["company"]
    domain  = ctx["domain"]
    ticket  = abs(hash(first + company)) % 90000 + 10000

    script = f"""=== OPENING ===
"Good [morning/afternoon], may I speak with {first}?"
[Wait for confirmation]
"Hi {first}, this is [YOUR NAME] calling from {company} IT Support. I hope I'm not catching you at a bad time?"

=== PRETEXT ===
"The reason I'm calling is that our security monitoring system has flagged some unusual activity on your account over the last 24 hours. We've had a few cases of credential stuffing affecting accounts in your department, and your account came up in our audit."

"I just need to verify a couple of things to make sure your account hasn't been compromised. This will only take two minutes."

=== KEY QUESTIONS ===
1. "First, can you confirm you're still using the same email address — {ctx['email'] or '[their email]'}?"
2. "Have you received any unusual login notifications or password reset emails recently?"
3. "Are you currently logged in to [VPN / portal]? We're seeing a session we can't attribute to your usual device."
4. "I'm going to need to reset your credentials as a precaution. Can you confirm your current password so I can verify it matches our system record before issuing a new one?"
   [OBJECTIVE: credential capture]

=== ALTERNATIVE OBJECTIVE (phishing link delivery) ===
"I'm going to send you a link to our secure verification portal. Can you open it on your device right now while I'm on the line?"
"Just enter your {company} username and current password to confirm your identity, and I'll complete the security check on my end."

=== OBJECTIONS ===
"How do I know you're really from IT?"
→ "Totally fair question. You can call the main IT helpdesk — helpdesk@{domain} has the number — and ask them to confirm I'm working ticket INC-{ticket}. I'll hold."
  [Note: by the time they call back you'll have your answer, or they may not bother]

"I should check with my manager first."
→ "Of course, but please be quick — the security window closes in 30 minutes and we'll have to lock the account if we can't verify it. Your manager can call me back on this same number."

=== CLOSING ===
"Thanks {first}, I've updated the ticket. You'll receive a confirmation email from it-support@{domain} shortly. Have a great day!"
"""

    notes = [
        f"Spoof caller ID to an internal {company} number if possible",
        "Call during business hours (9–11am or 2–4pm) — peak helpdesk time adds credibility",
        f"Ticket reference INC-{ticket} — memorise it before calling",
        "If target asks to call back, give a number you control (Twilio / Google Voice)",
    ]
    if ctx["breaches"]:
        notes.insert(0, f"Target is in {len(ctx['breaches'])} breach(es) ({', '.join(ctx['breaches'][:2])}) — mentioning 'credential stuffing' will resonate strongly")
    if ctx["has_vpn"]:
        notes.append("Target uses VPN — mention VPN session anomaly for added specificity")

    return {
        "script":    script,
        "notes":     notes,
        "pretext":   "IT security account audit",
        "objective": "Credential capture or phishing link delivery",
        "difficulty": "Medium",
    }


# ── 2. HR Survey / Policy Update ─────────────────────────────────────────────

@_register("hr_survey", "HR Survey", "HR calling to conduct a mandatory staff survey or confirm policy acknowledgement", "bi-clipboard2-check")
def script_hr_survey(ctx: dict) -> dict:
    first   = ctx["first_name"]
    company = ctx["company"]
    domain  = ctx["domain"]

    script = f"""=== OPENING ===
"Good [morning/afternoon], could I speak with {first} please?"
[Wait]
"Hi {first}, my name is [YOUR NAME] from {company} HR. How are you today?"

=== PRETEXT ===
"I'm calling as part of our annual staff engagement survey — it's mandatory this year as we're updating our compliance framework ahead of the audit. It'll only take 3–4 minutes."

=== INFORMATION GATHERING ===
1. "Can you confirm your current job title and department?"
2. "And your direct manager's name?"
3. "What's the best email to send your survey completion certificate to?"
   [Confirm/obtain email address]
4. "Are you currently working remotely or from the office?"
5. "What systems do you use day-to-day? We're updating our software inventory."
   [Map access: VPN, email client, key apps]

=== PIVOT TO CREDENTIAL OBJECTIVE ===
"Perfect. I'm going to send the survey link to {ctx['email'] or 'your work email'} right now — can you keep an eye out for it? It'll come from hr-survey@{domain}."
"The survey requires you to log in with your {company} credentials to verify your identity before submitting."

=== DIRECT APPROACH (if rapport is established) ===
"Actually, to save time — I can complete the verification with you now over the phone. Can you confirm your username and password? I just need to mark the record as verified in our system."

=== OBJECTIONS ===
"I didn't know about this survey."
→ "It was announced in last week's all-staff email from [HR Director name]. Your manager [name] should have briefed the team. There's been a lot going on so it might have got buried."

"I don't give out my password over the phone."
→ "Absolutely, that's the right instinct for external callers! I'll send you the link instead and you can log in directly."
  [PIVOT: deliver phishing link]

=== CLOSING ===
"Thanks so much {first}, I'll note you as verified. Keep an eye on your inbox for the survey link!"
"""

    notes = [
        "Research the real HR director's name before calling — drop it naturally",
        f"Spoof caller ID from an internal {company} number",
        "Information gathering (manager, systems) is valuable even if credential capture fails",
        "Best times: Monday morning or Friday afternoon when people are more distracted",
    ]
    if ctx["position"]:
        notes.append(f"Target's known position: {ctx['position']} — tailor department references")

    return {
        "script":    script,
        "notes":     notes,
        "pretext":   "Mandatory HR staff survey",
        "objective": "Information gathering + credential harvest / phishing link delivery",
        "difficulty": "Low",
    }


# ── 3. Bank / Finance Security Alert ─────────────────────────────────────────

@_register("bank_alert", "Bank Security Alert", "Impersonate the target's bank or finance team with a fraud alert", "bi-bank")
def script_bank_alert(ctx: dict) -> dict:
    first   = ctx["first_name"]
    company = ctx["company"]
    case_no = abs(hash(first + company)) % 90000 + 10000

    script = f"""=== OPENING ===
"Good [morning/afternoon], am I speaking with {first}?"
[Wait]
"Hello {first}, my name is [YOUR NAME] and I'm calling from the fraud prevention team at [BANK NAME]. I apologise for calling unexpectedly — this is regarding your business account."

=== PRETEXT ===
"We've detected some transactions on your account in the last 2 hours that have triggered our fraud detection system. We've temporarily placed a precautionary hold on two outgoing transfers pending your verification."

"I need to confirm your identity and go through a couple of security questions to release the hold. This is time-sensitive — the hold will expire and the transactions may process automatically if we can't verify within the hour."

=== VERIFICATION SEQUENCE ===
1. "Can you confirm your full name for me?"
2. "And the last 4 digits of the account number?"
   [Note the digits they provide]
3. "What's the registered email on the account?"
   [Capture email]
4. "I'm going to trigger a one-time verification code to your registered number — please tell me when you're ready."
   [When they receive the real OTP, ask: "What code did you receive?"]
   [OBJECTIVE: OTP interception / account takeover]

=== ALTERNATIVE: CALL TRANSFER ATTACK ===
"I'm going to transfer you to our automated verification system. Please have your full account number and online banking password ready — the system will ask you to key them in."
[Transfer to a voice system you control]

=== OBJECTIONS ===
"How do I know you're really from the bank?"
→ "You're right to be cautious. Hang up and call the number on the back of your card — ask to be put through to the fraud team and reference case FRD-{case_no}. I'll be waiting on this case."

"I don't give banking details over the phone."
→ "I completely understand. The alternative is to log in to online banking and approve the block from there — the suspicious transactions are showing under 'Pending' right now. I can walk you through it."

=== CLOSING ===
"Thank you {first}. I've noted your verification — the hold should lift within 15 minutes. You'll receive a confirmation SMS shortly."
"""

    notes = [
        "Research which bank the target uses before calling — LinkedIn, company website, job postings",
        "OTP interception requires real-time coordination — have a capture page ready before calling",
        "Works best on finance/accounting staff who are primed to handle bank calls",
        "Spoof caller ID to match the bank's published fraud team number",
    ]
    if company:
        notes.append(f"Target works at {company} — look up their corporate banking provider if possible")

    return {
        "script":    script,
        "notes":     notes,
        "pretext":   "Bank fraud alert / account hold",
        "objective": "OTP interception / banking credentials",
        "difficulty": "High",
    }


# ── 4. Executive Assistant / CEO Call ────────────────────────────────────────

@_register("exec_assistant", "Executive Assistant", "Impersonate a CEO's PA requesting urgent action from a staff member", "bi-person-badge")
def script_exec_assistant(ctx: dict) -> dict:
    first   = ctx["first_name"]
    company = ctx["company"]
    domain  = ctx["domain"]

    script = f"""=== OPENING ===
"Hi, is this {first}?"
[Wait]
"Hi {first}, my name is [YOUR NAME] — I'm the executive assistant to [CEO NAME] here at {company}. I'm calling on [his/her] behalf — [he/she] is currently in a board meeting and asked me to reach out to you directly."

=== PRETEXT ===
"[CEO NAME] is trying to finalise something urgently before end of day and needs your help. There's a time-sensitive vendor payment that needs to go out today, and [he/she] needs someone in [target's department] to authorise it. The finance team is unavailable — [CFO NAME] is travelling."

=== ESCALATION SEQUENCE ===
1. "Can you confirm you have authority to approve payments up to [amount]?"
2. "The invoice details are: [VENDOR NAME], amount [X], reference [REF]. Can you process that today?"
3. "The payment details will be sent to your email shortly from [ceo-pa@{domain}]. Please process it as soon as you receive it."
   [OBJECTIVE: action a fraudulent invoice / reveal the authorisation process]

=== INFORMATION GATHERING VARIANT ===
"Before I send through the details, I need to confirm the correct procedure. Could you walk me through how you'd typically process an urgent vendor payment? Who else would need to sign off?"
[Map the approval chain, payment systems used, authorisation thresholds]

=== OBJECTIONS ===
"I should check with [CEO NAME] directly."
→ "[CEO NAME] is in a confidential board session and can't take calls right now. That's exactly why [he/she] asked me to reach out to you — [he/she] said you'd be the right person to trust with this."

"Can you email me the details?"
→ "Of course, I'll send them right now to {ctx['email'] or 'your email'}. The email will come from [ceo-pa@{domain}]. Could you confirm that address is correct for you?"
  [PIVOT: deliver phishing email with macro-laced invoice]

=== CLOSING ===
"Perfect, thank you so much {first}. [CEO NAME] will really appreciate this. I'll send those details over now — please let me know once you've processed it."
"""

    notes = [
        f"Research {company}'s CEO and CFO names from LinkedIn / company website before calling",
        "Target finance, HR, or admin staff who are likely to handle payments/authorisations",
        "Follow up IMMEDIATELY with a phishing email (fake invoice) — the call legitimises it",
        "Open rates on follow-up emails are near 100% after this pretext",
    ]
    if ctx["position"]:
        notes.append(f"Target position ({ctx['position']}) — assess whether they have payment authority")

    return {
        "script":    script,
        "notes":     notes,
        "pretext":   "CEO / BEC urgent payment request",
        "objective": "Fraudulent wire transfer authorisation or payment process mapping",
        "difficulty": "Medium",
    }


# ── 5. Vendor / Supplier Verification ────────────────────────────────────────

@_register("vendor_call", "Vendor Verification", "Impersonate a known vendor calling to update banking details", "bi-shop")
def script_vendor_call(ctx: dict) -> dict:
    first   = ctx["first_name"]
    company = ctx["company"]
    domain  = ctx["domain"]

    script = f"""=== OPENING ===
"Good [morning/afternoon], could I speak with someone in accounts payable / finance?"
[Transferred or answered]
"Hi {first}, my name is [YOUR NAME] from [VENDOR NAME]. We've been working with {company} for [X] years. I'm calling about an urgent update regarding our banking details."

=== PRETEXT ===
"Our bank has migrated us to a new account following a merger, and we're contacting all our clients to update payment records before our old account closes at the end of the month. Any payments made to the old account after [DATE] will be delayed or returned."

=== INFORMATION GATHERING ===
1. "Can I confirm you're the right person to handle this, or should I speak with someone in accounts payable?"
2. "What's the best email to send the formal change notification to?"
3. "Could you confirm what account details you currently have on file for us, so I can make sure the transition is clean?"
   [Note what they confirm — then 'correct' them with your account details]
4. "We'll send a formal letter with our new sort code and account number. Would that go to {ctx['email'] or 'your email'} or a finance team address?"

=== THE ASK ===
"I'll send over a formal notification with our new details. In the meantime, could you make a note in your system that payments from [DATE] should go to the new account? I can hold while you find the right screen."
[Walk them through updating vendor banking details to your account]

=== OBJECTIONS ===
"We have a process — we need a letter on headed paper."
→ "Absolutely, I'll email that over right now. Could you confirm the email address? And do you have a specific format you need us to follow?"
  [Capture the process AND deliver a phishing document]

"I need to verify this with my manager."
→ "Of course — that's great practice. My direct number is [number you control]. The formal notification will arrive from accounts@[VENDOR-DOMAIN] in the next few minutes."

=== CLOSING ===
"Excellent, thank you {first}. I'll get that formal notification over to you now. Just to confirm — you'll update the payment details once you receive the letter?"
"""

    notes = [
        f"Research {company}'s real vendors from LinkedIn, job postings, or their website before calling",
        "Accounts payable / finance staff are the ideal target for this pretext",
        "Classic mandate fraud pretext — high success rate, low suspicion",
        "Follow up immediately with a phishing email containing a fake 'bank change notification'",
    ]

    return {
        "script":    script,
        "notes":     notes,
        "pretext":   "Vendor banking detail update (mandate fraud)",
        "objective": "Update vendor banking details to attacker-controlled account",
        "difficulty": "Low",
    }


# ── Public API ────────────────────────────────────────────────────────────────

def list_scripts() -> list[dict]:
    return [
        {"key": k, "label": v["label"], "description": v["description"], "icon": v["icon"]}
        for k, v in SCRIPTS.items()
    ]


def generate(scan: dict, script_key: str) -> dict:
    """Generate a vishing call script from a scan record using the specified template."""
    if script_key not in SCRIPTS:
        return {"error": f"Unknown script: {script_key}"}
    ctx    = build_context(scan)
    result = SCRIPTS[script_key]["fn"](ctx)
    result["context"]    = {k: v for k, v in ctx.items() if not isinstance(v, list) or k == "breaches"}
    result["script_key"] = script_key
    return result
