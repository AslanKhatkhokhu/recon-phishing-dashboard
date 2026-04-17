"""
Profile Builder — RedBalance
Aggregates all OSINT data for each person found in a scan,
identifies weak points, and recommends phishing approaches.
"""

# ── Weak point analysis ───────────────────────────────────────────────────────

_TEMPLATE_MAP = {
    "Management":   ("ceo_fraud",       "Authority — impersonate a superior or board member"),
    "Finance":      ("ceo_fraud",       "Authority + urgency — wire transfer or invoice fraud"),
    "HR":           ("credential_reset","HR systems access — fake HRIS portal reset"),
    "IT":           ("vpn_access",      "IT controls — fake VPN certificate renewal"),
    "Engineering":  ("document_share",  "Code review / document share — fake GitHub/Confluence link"),
    "Research":     ("document_share",  "Paper/data share — fake research portal login"),
    "Marketing":    ("document_share",  "Campaign asset share — fake Google Drive / Adobe link"),
    "Sales":        ("credential_reset","CRM access — fake Salesforce reset"),
    "Legal":        ("security_alert",  "Compliance urgency — fake legal portal or DocuSign"),
    "Product":      ("document_share",  "Roadmap / spec doc share — fake Notion/Confluence"),
    "Design":       ("document_share",  "Asset share — fake Figma / Creative Cloud link"),
    "Support":      ("it_helpdesk",     "Helpdesk — impersonate IT support requesting access"),
    "Operations":   ("vpn_access",      "Operations access — fake ERP/VPN credential renewal"),
}

_DEFAULT_TEMPLATE = ("credential_reset", "Generic credential reset — Microsoft/Google account")


def _weak_points(person: dict, scan_results: dict) -> list[str]:
    """Return a list of identified weak points for this person."""
    points = []
    name  = person.get("name", "")
    title = (person.get("title", "") or "").lower()
    dept  = person.get("department", "")

    # Breaches
    hibp = scan_results.get("hibp", {})
    if hibp.get("breaches"):
        bnames = [b.get("Name", b) for b in hibp["breaches"][:3]]
        points.append(f"Data breach exposure: {', '.join(str(b) for b in bnames)}")

    # Known email confirmed valid
    if person.get("email"):
        points.append(f"Confirmed email address: {person['email']}")

    # Social profiles
    profiles = []
    sherlock = scan_results.get("sherlock", {})
    if sherlock.get("profiles"):
        profiles += [p.get("url", "") for p in sherlock["profiles"][:2]]
    wmn = scan_results.get("whatsmyname", {})
    if wmn.get("profiles"):
        profiles += [p.get("url", "") for p in wmn["profiles"][:2]]
    if profiles:
        points.append(f"Public social profiles found: {', '.join(profiles[:3])}")

    # GitHub activity
    github = scan_results.get("github", {})
    if github.get("repos"):
        points.append(f"Active GitHub repositories: {len(github['repos'])} repos public")

    # GitFive emails
    gitfive = scan_results.get("gitfive", {})
    if gitfive.get("possible_emails"):
        points.append(f"Possible emails from GitHub: {', '.join(gitfive['possible_emails'][:2])}")

    # Seniority / access level
    if any(kw in title for kw in ["ceo","cto","ciso","cfo","coo","vp","director","head","chief","president"]):
        points.append("Senior/executive role — high-value target, likely has broad system access")
    elif any(kw in title for kw in ["admin","sysadmin","engineer","devops","it "]):
        points.append("Technical role — likely has privileged system/network access")
    elif any(kw in title for kw in ["finance","accounting","payroll","controller","treasurer"]):
        points.append("Finance role — likely has access to payment systems and bank accounts")
    elif any(kw in title for kw in ["hr","people","talent","recruiter"]):
        points.append("HR role — has access to employee PII, payroll, and sensitive records")

    # Email candidates = more attack surface
    cands = person.get("email_candidates", [])
    if len(cands) > 3:
        points.append(f"{len(cands)} email format candidates to try")

    if not points:
        points.append("Limited public information — generic approach recommended")

    return points


def _phishing_recommendation(person: dict) -> dict:
    dept = person.get("department", "")
    template_key, rationale = _TEMPLATE_MAP.get(dept, _DEFAULT_TEMPLATE)
    name_parts = person.get("name", "Target").split()
    first = name_parts[0] if name_parts else "there"
    title = person.get("title", "")

    # Build a short personalised pretext
    pretext_extras = []
    if title:
        pretext_extras.append(f"Reference their role ({title}) to add credibility.")
    if dept:
        pretext_extras.append(f"Frame around {dept} department workflows.")

    return {
        "template":  template_key,
        "rationale": rationale,
        "pretext":   " ".join(pretext_extras) or "Use name personalisation to increase open rate.",
        "greeting":  f"Dear {first},",
    }


# ── Public API ────────────────────────────────────────────────────────────────

def build_profiles(scan: dict) -> list[dict]:
    """
    Build a profile for every person found in web_scrape results.
    Returns a list of profile dicts enriched with weak_points + phishing recommendation.
    """
    results = scan.get("results", {})
    web     = results.get("web_scrape", {})
    people  = web.get("people", [])

    profiles = []
    for person in people:
        profile = dict(person)
        profile["weak_points"]   = _weak_points(person, results)
        profile["phishing"]      = _phishing_recommendation(person)
        profiles.append(profile)

    return profiles
