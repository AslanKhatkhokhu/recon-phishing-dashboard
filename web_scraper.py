"""
Web Scraper — RedBalance OSINT
Crawls a company website to extract employee names, job titles, departments, and emails.

Strategies (run in order, results merged):
  1. Schema.org JSON-LD extraction
  2. Heading + sibling extraction
  3. Card-pattern extraction
  4. JS bundle mining (finds embedded person objects in React/Vue bundles)
  5. Sitemap.xml page discovery
  6. Internal link following (people-related URLs found on crawled pages)
  7. AI extraction (Claude or OpenAI) — used when heuristics find nothing on a page
"""

import re
import urllib.parse
import urllib.request
import urllib.error
import ssl
import json
import os
import time

try:
    from bs4 import BeautifulSoup
    _BS4 = True
except ImportError:
    _BS4 = False

# ── Common people pages to probe ─────────────────────────────────────────────

_PEOPLE_PATHS = [
    "/about", "/about-us", "/about/team", "/about/people",
    "/team", "/our-team", "/the-team", "/meet-the-team",
    "/people", "/our-people", "/staff", "/our-staff",
    "/leadership", "/leadership-team", "/management", "/management-team",
    "/executives", "/board", "/board-of-directors",
    "/contact", "/contact-us", "/company", "/company/team",
    "/en/about", "/en/team", "/en/people",
    # .html variants (static sites, Apache/Nginx without rewrite rules)
    "/team.html", "/our-team.html", "/meet-the-team.html",
    "/people.html", "/staff.html", "/about.html", "/about-us.html",
    "/leadership.html", "/management.html", "/executives.html",
    "/board.html", "/contact.html", "/contact-us.html",
    "/partners.html", "/home.html", "/index.html",
]

# Keywords that indicate a link might lead to a people page
_PEOPLE_LINK_PATTERNS = re.compile(
    r'(team|people|staff|about|leadership|management|executives|board|'
    r'who-we-are|meet|directory|members|partners|founders)',
    re.IGNORECASE,
)

# ── Name-detection helpers ────────────────────────────────────────────────────

_TITLE_STOPWORDS = {
    "About", "Team", "Staff", "People", "Board", "Leadership", "Management",
    "Contact", "Home", "News", "Blog", "Press", "Work", "Join", "Company",
    "Services", "Products", "Solutions", "Privacy", "Terms", "Cookie",
    "Login", "Sign", "Get", "Our", "The", "More", "View", "All", "Meet",
    "New", "Read", "Watch", "Learn", "See", "Find", "Your", "Its", "With",
    "From", "For", "How", "Why", "Who", "What", "When", "Where",
    # Common false-positive headings on corporate sites
    "Open", "Graph", "Office", "Hours", "Global", "Energy", "Safety",
    "Operations", "Future", "Key", "Functions", "North", "South", "Years",
    "Active", "Exploration", "Campaigns", "Adriatic", "Processing",
    "Valletta", "Malta", "Offshore", "Onshore", "Platform", "Refinery",
    "Latest", "Updates", "Ready", "Visit",
    "East", "West", "Mediterranean", "Renewable", "Marine", "Gas",
}

_TITLE_KEYWORDS = [
    "ceo", "cto", "coo", "cfo", "ciso", "vp", "vice president",
    "director", "head of", "head,", "manager", "lead", "senior", "junior",
    "engineer", "developer", "designer", "analyst", "architect", "consultant",
    "advisor", "officer", "president", "founder", "partner", "principal",
    "specialist", "coordinator", "associate", "executive", "intern",
    "administrator", "supervisor", "technician", "researcher", "scientist",
    "geologist", "geophysicist", "petroleum", "drilling", "reservoir",
]

_DEPT_KEYWORDS = {
    "Engineering":  ["engineer", "developer", "devops", "infrastructure", "software", "hardware", "qa", "testing", "petroleum", "drilling", "reservoir"],
    "IT":           ["it ", "information technology", "sysadmin", "network", "security", "cyber"],
    "Finance":      ["finance", "financial", "accounting", "accountant", "controller", "cfo", "treasurer"],
    "HR":           ["human resources", "hr", "people ops", "talent", "recruitment", "recruiter"],
    "Marketing":    ["marketing", "brand", "growth", "content", "seo", "social media", "communications"],
    "Sales":        ["sales", "account executive", "business development", "bdr", "sdr"],
    "Legal":        ["legal", "counsel", "compliance", "attorney", "lawyer", "general counsel"],
    "Operations":   ["operations", "ops", "coo", "supply chain", "logistics"],
    "Product":      ["product", "pm ", "product manager", "product owner", "ux", "ui"],
    "Design":       ["design", "designer", "creative", "art director", "ux", "ui"],
    "Management":   ["ceo", "cto", "ciso", "cfo", "coo", "president", "vp", "director", "head of", "chief"],
    "Research":     ["research", "r&d", "scientist", "data scientist", "machine learning", "ai", "geologist", "geophysicist", "exploration"],
    "Support":      ["support", "customer success", "helpdesk", "help desk", "service desk"],
}


def _dept_from_title(title: str) -> str:
    t = title.lower()
    for dept, keywords in _DEPT_KEYWORDS.items():
        if any(kw in t for kw in keywords):
            return dept
    return ""


def _looks_like_name(text: str) -> bool:
    text = text.strip()
    if not text or len(text) < 4 or len(text) > 60:
        return False
    words = text.split()
    if len(words) < 2 or len(words) > 4:
        return False
    if any(w in _TITLE_STOPWORDS for w in words):
        return False
    if not all(re.match(r'^[A-Z][a-záéíóúäöüàèìòùñ\.\-\']+$', w) for w in words):
        return False
    if any(c in text for c in ['/', '|', '\\', '@', '&', '(', ')']):
        return False
    return True


def _looks_like_title(text: str) -> bool:
    t = text.lower().strip()
    return any(kw in t for kw in _TITLE_KEYWORDS)


# ── HTTP helper ───────────────────────────────────────────────────────────────

_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode    = ssl.CERT_NONE

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def _fetch(url: str, timeout: int = 12) -> str | None:
    try:
        req = urllib.request.Request(url, headers=_HEADERS)
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=timeout) as r:
            charset = r.headers.get_content_charset() or "utf-8"
            return r.read().decode(charset, errors="replace")
    except Exception:
        return None


# ── Sitemap discovery ─────────────────────────────────────────────────────────

def _fetch_sitemap_urls(base_url: str, log) -> list[str]:
    """Try sitemap.xml and sitemap_index.xml — return URLs relevant to people pages."""
    urls: list[str] = []
    for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap", "/sitemap.txt"]:
        raw = _fetch(base_url + path)
        if not raw:
            continue
        # Extract <loc> entries
        locs = re.findall(r'<loc>([^<]+)</loc>', raw)
        if not locs and path.endswith(".txt"):
            locs = [line.strip() for line in raw.splitlines() if line.strip().startswith("http")]
        people_locs = [l for l in locs if _PEOPLE_LINK_PATTERNS.search(l)]
        if people_locs:
            log(f"Sitemap: found {len(people_locs)} people-related URLs from {path}")
        urls.extend(people_locs[:8])  # cap per sitemap
        if urls:
            break
    return list(dict.fromkeys(urls))  # deduplicate, preserve order


# ── Internal link following ───────────────────────────────────────────────────

def _extract_internal_links(soup, base_url: str, seen: set) -> list[str]:
    """Find internal links on a page that look like people/team pages."""
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith("#") or href.startswith("mailto:"):
            continue
        # Make absolute
        if href.startswith("/"):
            href = base_url + href
        elif not href.startswith("http"):
            href = base_url + "/" + href
        # Same domain only
        if urllib.parse.urlparse(base_url).netloc not in href:
            continue
        if href in seen:
            continue
        # Check if URL or link text looks like a people page
        link_text = a.get_text(" ", strip=True)
        if _PEOPLE_LINK_PATTERNS.search(href) or _PEOPLE_LINK_PATTERNS.search(link_text):
            links.append(href)
    return list(dict.fromkeys(links))[:10]  # deduplicate, cap


# ── JS bundle mining ──────────────────────────────────────────────────────────

# Match JS object fields we care about
_JS_NAME_RE   = re.compile(r'(?:name|fullName)\s*:\s*"([A-Z][a-záéíóúäöü\-]+(?: [A-Z][a-záéíóúäöü\-]+){1,3})"')
_JS_ROLE_RE   = re.compile(r'(?:role|title|position|jobTitle)\s*:\s*"([^"]{3,80})"')
_JS_EMAIL_RE  = re.compile(r'(?:email|mail)\s*:\s*"([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,})"', re.IGNORECASE)
_JS_DEPT_RE   = re.compile(r'(?:department|dept|division|group|team)\s*:\s*"([^"]{2,60})"')
_JS_DESC_RE   = re.compile(r'(?:description|bio|about|summary)\s*:\s*"([^"]{20,600})"')
_JS_FUNCS_RE  = re.compile(r'functions\s*:\s*\[([^\]]{10,500})\]')


def _extract_people_from_js(js: str, source_label: str) -> list[dict]:
    """Extract person objects from a block of JavaScript text."""
    people: list[dict] = []
    for m in _JS_NAME_RE.finditer(js):
        name = m.group(1).strip()
        if not _looks_like_name(name):
            continue
        # Search in a window around this name for role/email/dept
        start = max(0, m.start() - 50)
        end   = min(len(js), m.end() + 600)
        window = js[start:end]

        role_m  = _JS_ROLE_RE.search(window)
        email_m = _JS_EMAIL_RE.search(window)
        dept_m  = _JS_DEPT_RE.search(window)
        desc_m  = _JS_DESC_RE.search(window)
        func_m  = _JS_FUNCS_RE.search(window)

        role  = role_m.group(1)  if role_m  else ""
        email = email_m.group(1) if email_m else ""
        dept  = dept_m.group(1)  if dept_m  else ""
        desc  = desc_m.group(1)  if desc_m  else ""

        # Parse functions list: ["item1","item2",...]
        functions = []
        if func_m:
            functions = re.findall(r'"([^"]{3,80})"', func_m.group(1))

        # Require at least a role or email — filters out facility/company names
        if not role and not email:
            continue

        if not dept and role:
            dept = _dept_from_title(role)

        people.append({
            "name":        name,
            "title":       role,
            "department":  dept,
            "email":       email,
            "description": desc,
            "functions":   functions,
            "source":      source_label,
        })
    return people


def _mine_js_bundles(html: str, base_url: str, log) -> list[dict]:
    """
    Extract person objects from JS — both external bundles and inline scripts.
    Looks for React/Vue style: {name:"...", role:"...", email:"..."}
    """
    people: list[dict] = []

    # ── Phase A: mine inline <script> blocks ────────────────────────
    inline_scripts = re.findall(r'<script(?:\s[^>]*)?>(.+?)</script>', html, re.DOTALL)
    for i, block in enumerate(inline_scripts):
        if len(block) < 80:
            continue
        found = _extract_people_from_js(block, "inline-script")
        if found:
            log(f"  Inline script #{i+1}: found {len(found)} people")
            people.extend(found)

    if people:
        return people

    # ── Phase B: mine external .js bundles ──────────────────────────
    script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html)
    # Prefer larger bundles (index, main, app, chunk)
    priority = [s for s in script_srcs if any(k in s for k in ['index', 'main', 'app', 'chunk'])]
    others   = [s for s in script_srcs if s not in priority]
    ordered  = (priority + others)[:5]  # check up to 5 bundles

    for src in ordered:
        if src.startswith("/"):
            src = base_url + src
        elif not src.startswith("http"):
            src = base_url + "/" + src

        log(f"Mining JS bundle: {src.split('/')[-1]}")
        js = _fetch(src)
        if not js or len(js) < 1000:
            continue

        found = _extract_people_from_js(js, "js-bundle")
        if found:
            log(f"  JS bundle: found {len(found)} people")
            people.extend(found)
            break  # found data — no need to scan more bundles

    return people


# ── AI extraction ─────────────────────────────────────────────────────────────

def _ai_extract_people(page_text: str, url: str, log) -> list[dict]:
    """
    Send page text to Claude or OpenAI and ask it to extract people.
    API key read from env vars — never hardcoded.
    Returns list of person dicts.
    """
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    openai_key    = os.environ.get("OPENAI_API_KEY", "")

    if not anthropic_key and not openai_key:
        log("AI extraction skipped — no API key set (ANTHROPIC_API_KEY or OPENAI_API_KEY)")
        return []

    # Truncate text to keep costs low
    text = page_text[:6000].strip()
    if not text:
        return []

    prompt = (
        "Extract all employees/team members from the following webpage content. "
        "Return ONLY a JSON array (no markdown, no explanation) where each element has: "
        "name (string), title (string), department (string), email (string — empty string if not found). "
        "If no people are found, return []. "
        "Webpage content:\n\n" + text
    )

    if anthropic_key:
        return _ai_call_anthropic(prompt, anthropic_key, log)
    else:
        return _ai_call_openai(prompt, openai_key, log)


def _ai_call_anthropic(prompt: str, api_key: str, log) -> list[dict]:
    model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    log(f"AI extraction: calling Claude ({model})…")
    body = json.dumps({
        "model": model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "x-api-key":         api_key,
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read())
        text = resp["content"][0]["text"].strip()
        return _parse_ai_response(text, log)
    except Exception as e:
        log(f"AI (Anthropic) error: {e}")
        return []


def _ai_call_openai(prompt: str, api_key: str, log) -> list[dict]:
    log("AI extraction: calling OpenAI API…")
    body = json.dumps({
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1024,
        "response_format": {"type": "json_object"},
    }).encode()
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            resp = json.loads(r.read())
        text = resp["choices"][0]["message"]["content"].strip()
        return _parse_ai_response(text, log)
    except Exception as e:
        log(f"AI (OpenAI) error: {e}")
        return []


def _parse_ai_response(text: str, log) -> list[dict]:
    """Parse the LLM JSON response into person dicts."""
    # Strip markdown fences if present
    text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'```\s*$', '', text, flags=re.MULTILINE)
    text = text.strip()

    # Handle {people: [...]} wrapper
    if text.startswith("{"):
        try:
            obj = json.loads(text)
            # Find the array inside
            for v in obj.values():
                if isinstance(v, list):
                    text = json.dumps(v)
                    break
        except Exception:
            pass

    try:
        data = json.loads(text)
        if not isinstance(data, list):
            return []
        people = []
        for item in data:
            if not isinstance(item, dict):
                continue
            name  = str(item.get("name", "") or "").strip()
            title = str(item.get("title", "") or item.get("role", "") or item.get("position", "") or "").strip()
            dept  = str(item.get("department", "") or item.get("dept", "") or "").strip()
            email = str(item.get("email", "") or "").strip()
            if not name or len(name) < 3:
                continue
            if not dept and title:
                dept = _dept_from_title(title)
            people.append({
                "name":       name,
                "title":      title,
                "department": dept,
                "email":      email,
                "source":     "ai",
            })
        log(f"AI extraction: found {len(people)} people")
        return people
    except Exception as e:
        log(f"AI response parse error: {e} — raw: {text[:200]}")
        return []


# ── Schema.org extraction ─────────────────────────────────────────────────────

def _extract_schema_persons(soup) -> list[dict]:
    people = []
    for tag in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(tag.string or "")
            items = data if isinstance(data, list) else [data]
            for item in items:
                if "@graph" in item:
                    items += item["@graph"]
                t = item.get("@type", "")
                if "Person" in str(t):
                    name  = item.get("name", "")
                    title = item.get("jobTitle", "")
                    email = item.get("email", "")
                    dept  = item.get("worksFor", {})
                    if isinstance(dept, dict):
                        dept = dept.get("name", "")
                    elif isinstance(dept, list) and dept:
                        dept = dept[0].get("name", "") if isinstance(dept[0], dict) else ""
                    else:
                        dept = ""
                    if name:
                        people.append({
                            "name":       name.strip(),
                            "title":      title.strip(),
                            "department": dept.strip() or _dept_from_title(title),
                            "email":      email.strip(),
                            "source":     "schema.org",
                        })
        except Exception:
            pass
    return people


# ── Card-pattern extraction ───────────────────────────────────────────────────

def _extract_cards(soup) -> list[dict]:
    people = []
    seen   = set()
    title_tags = []
    for tag in soup.find_all(string=True):
        text = tag.strip()
        if _looks_like_title(text) and len(text) < 120:
            title_tags.append(tag)

    for ttag in title_tags:
        title_text = ttag.strip()
        container  = ttag.parent
        for _ in range(4):
            if container is None:
                break
            for candidate in container.find_all(string=True):
                ctext = candidate.strip()
                if _looks_like_name(ctext) and ctext not in seen:
                    key = (ctext, title_text[:40])
                    if key not in seen:
                        seen.add(key)
                        seen.add(ctext)
                        people.append({
                            "name":       ctext,
                            "title":      title_text,
                            "department": _dept_from_title(title_text),
                            "email":      "",
                            "source":     "card-pattern",
                        })
                    break
            container = container.parent
    return people


# ── Heading+subtitle extraction ───────────────────────────────────────────────

def _extract_headings(soup) -> list[dict]:
    people = []
    seen   = set()
    for tag in soup.find_all(["h2", "h3", "h4"]):
        text = tag.get_text(" ", strip=True)
        if not _looks_like_name(text):
            continue
        if text in seen:
            continue
        title = ""
        for sib in [tag.find_next_sibling(), tag.find("p"), tag.find("span")]:
            if sib:
                st = sib.get_text(" ", strip=True)
                if _looks_like_title(st) and len(st) < 100:
                    title = st
                    break
        seen.add(text)
        people.append({
            "name":       text,
            "title":      title,
            "department": _dept_from_title(title),
            "email":      "",
            "source":     "heading",
        })
    return people


# ── Email extraction ──────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')


def _extract_emails(html: str) -> list[str]:
    return list(set(_EMAIL_RE.findall(html)))


# ── Merge and deduplicate ─────────────────────────────────────────────────────

def _merge(people: list[dict]) -> list[dict]:
    by_name: dict[str, dict] = {}
    for p in people:
        norm = p["name"].strip().lower()
        if norm not in by_name:
            by_name[norm] = dict(p)
        else:
            existing = by_name[norm]
            if not existing["title"]      and p["title"]:      existing["title"]      = p["title"]
            if not existing["department"] and p["department"]: existing["department"] = p["department"]
            if not existing["email"]      and p["email"]:      existing["email"]      = p["email"]
    return list(by_name.values())


# ── Name → email candidates ───────────────────────────────────────────────────

def _name_to_email_candidates(name: str, domain: str) -> list[str]:
    parts = name.lower().split()
    if len(parts) < 2:
        return []
    first, last = parts[0], parts[-1]
    fi = first[0]
    clean = lambda s: re.sub(r'[^a-z0-9]', '', s)
    f, l = clean(first), clean(last)
    fi_c = clean(fi)
    return [
        f"{f}.{l}@{domain}",
        f"{f}{l}@{domain}",
        f"{fi_c}{l}@{domain}",
        f"{fi_c}.{l}@{domain}",
        f"{l}.{f}@{domain}",
        f"{l}{fi_c}@{domain}",
        f"{f}@{domain}",
        f"{l}@{domain}",
        f"{f}_{l}@{domain}",
    ]


# ── Public API ────────────────────────────────────────────────────────────────

def scrape(url: str, log_fn=None, max_pages: int = 15, ai: bool = True) -> dict:
    """
    Crawl a website and extract employee info using multiple strategies.
    Returns:
      {
        "people": [{"name","title","department","email","email_candidates","source"}],
        "emails_found": [...],
        "pages_crawled": [...],
        "domain": str,
        "ai_used": bool,
      }
    """
    def log(msg):
        if log_fn:
            log_fn(msg)

    if not _BS4:
        return {"error": "BeautifulSoup4 not installed", "people": [], "emails_found": []}

    parsed   = urllib.parse.urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    domain   = parsed.netloc.lstrip("www.")

    log(f"Base URL: {base_url}  |  Domain: {domain}")

    all_people: list[dict] = []
    all_emails: list[str]  = []
    crawled:    list[str]  = []
    seen_urls:  set[str]   = set()
    ai_used = False

    # Build initial queue: target URL + common people paths
    queue: list[str] = [url] + [base_url + p for p in _PEOPLE_PATHS]

    # Phase 1: fetch root page to mine JS bundles and discover links + sitemap
    log(f"Fetching root: {url}")
    root_html = _fetch(url)
    if root_html:
        seen_urls.add(url)
        crawled.append(url)

        # JS bundle mining on root page (catches SPAs like React/Vue)
        js_people = _mine_js_bundles(root_html, base_url, log)
        if js_people:
            log(f"JS bundles: {len(js_people)} people found")
            all_people.extend(js_people)

        # Discover internal people-page links on root
        root_soup = BeautifulSoup(root_html, "lxml")
        found_links = _extract_internal_links(root_soup, base_url, seen_urls)
        if found_links:
            log(f"Discovered {len(found_links)} internal people-related links")
            # Prioritise discovered links over generic probe paths
            queue = [url] + found_links + queue[1:]

        all_emails.extend(_extract_emails(root_html))

    # Phase 2: sitemap discovery
    sitemap_urls = _fetch_sitemap_urls(base_url, log)
    for su in sitemap_urls:
        if su not in seen_urls:
            queue.insert(1, su)

    # Phase 3: crawl the queue
    for page_url in queue:
        if len(crawled) >= max_pages:
            break
        if page_url in seen_urls:
            continue
        seen_urls.add(page_url)

        log(f"Crawling: {page_url}")
        html = _fetch(page_url)
        if not html:
            continue

        crawled.append(page_url)
        soup = BeautifulSoup(html, "lxml")

        # Remove nav/footer/header noise before heuristic extraction
        for noise in soup.find_all(["nav", "footer", "header", "script", "style"]):
            noise.decompose()

        people_here = (
            _extract_schema_persons(soup) +
            _extract_headings(soup) +
            _extract_cards(soup)
        )

        # Also mine JS bundles on this page if it's different from root
        if not people_here and page_url != url:
            js_people = _mine_js_bundles(html, base_url, log)
            people_here.extend(js_people)

        emails_here = _extract_emails(html)
        all_emails.extend(emails_here)

        # AI fallback: if heuristics found nothing on a page that looks relevant
        if not people_here and ai and _PEOPLE_LINK_PATTERNS.search(page_url):
            page_text = soup.get_text(" ", strip=True)[:6000]
            if len(page_text) > 200:
                ai_people = _ai_extract_people(page_text, page_url, log)
                if ai_people:
                    ai_used = True
                    people_here.extend(ai_people)

        if people_here:
            log(f"  Found {len(people_here)} people on {page_url.split(base_url)[-1] or '/'}")
        if emails_here:
            log(f"  Found {len(emails_here)} emails")

        all_people.extend(people_here)

        # Discover more links from this page
        if len(crawled) < max_pages:
            new_links = _extract_internal_links(soup, base_url, seen_urls)
            for lnk in new_links:
                if lnk not in seen_urls:
                    queue.append(lnk)

        time.sleep(0.25)

    # AI on root page text if NOTHING found at all
    if not all_people and ai and root_html:
        log("No people found via heuristics — running AI on root page text…")
        root_soup_clean = BeautifulSoup(root_html, "lxml")
        for n in root_soup_clean.find_all(["nav", "footer", "script", "style"]):
            n.decompose()
        page_text = root_soup_clean.get_text(" ", strip=True)
        ai_people = _ai_extract_people(page_text, url, log)
        if ai_people:
            ai_used = True
            all_people.extend(ai_people)

    # Merge duplicates
    merged = _merge(all_people)

    # Match raw emails to people, generate candidates for rest
    email_map = {e.split("@")[0].lower(): e for e in all_emails}
    for p in merged:
        if not p["email"]:
            parts = p["name"].lower().split()
            if len(parts) >= 2:
                f, l = parts[0], parts[-1]
                for key, em in email_map.items():
                    if f in key or l in key:
                        p["email"] = em
                        break
        p["email_candidates"] = _name_to_email_candidates(p["name"], domain)

    all_emails = list(set(all_emails))

    log(f"Done. People: {len(merged)} | Emails: {len(all_emails)} | Pages: {len(crawled)} | AI: {ai_used}")

    return {
        "people":        merged,
        "emails_found":  all_emails,
        "pages_crawled": crawled,
        "domain":        domain,
        "ai_used":       ai_used,
    }
