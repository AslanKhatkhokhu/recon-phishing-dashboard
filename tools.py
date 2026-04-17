"""
OSINT Tool Wrappers
Each method runs the tool via subprocess, parses its output,
and emits structured events to the scan queue.
"""

import subprocess
import shutil
import json
import re
import os
import time
import tempfile
import urllib.request
import urllib.error
import urllib.parse
from queue import Queue

# Directory where username wordlists are stored (alongside this file)
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))

# Wordlist files keyed by pattern name
_USERNAME_LISTS = {
    "jsmith":     os.path.join(_TOOLS_DIR, "jsmith.txt"),     # initiallastname   e.g. jsmith
    "john.smith": os.path.join(_TOOLS_DIR, "john.smith.txt"), # firstname.lastname e.g. john.smith
    "johnsmith":  os.path.join(_TOOLS_DIR, "johnsmith.txt"),  # firstnamelastname  e.g. johnsmith
    "j.smith":    os.path.join(_TOOLS_DIR, "jsmith.txt"),     # initial.lastname   no dedicated file — reuse jsmith
}

# Format functions: (first, last) → username string
_PATTERN_FORMATS = {
    "jsmith":     lambda f, l: f[0] + l,
    "j.smith":    lambda f, l: f[0] + "." + l,
    "john.smith": lambda f, l: f + "." + l,
    "johnsmith":  lambda f, l: f + l,
}

# Probe names: common first+last combos spanning English and German/Austrian names.
# Using real common names maximises the chance of hitting actual accounts.
_PROBE_NAMES = [
    ("michael", "huber"),   ("thomas",  "mayer"),
    ("stefan",  "gruber"),  ("markus",  "bauer"),
    ("christian","wagner"), ("peter",   "hofmann"),
    ("alexander","mueller"),("martin",  "berger"),
    ("andreas", "fischer"), ("daniel",  "schneider"),
    ("michael", "smith"),   ("david",   "jones"),
    ("john",    "smith"),   ("james",   "brown"),
    ("robert",  "wilson"),
]


def _check_o365(email: str) -> bool:
    """Return True if the Microsoft GetCredentialType API says this account exists."""
    try:
        payload = json.dumps({"Username": email}).encode()
        req = urllib.request.Request(
            "https://login.microsoftonline.com/common/GetCredentialType",
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return data.get("IfExistsResult", 0) in (1, 5, 6)
    except Exception:
        return False


def _infer_pattern_from_emails(emails: list[str]) -> str | None:
    """
    Try to infer the naming pattern from already-known email addresses.
    Returns pattern key or None if inconclusive.
    """
    votes: dict[str, int] = {p: 0 for p in _PATTERN_FORMATS}
    for email in emails[:30]:
        local = email.split("@")[0].lower()
        if "." in local:
            before = local.split(".")[0]
            votes["j.smith" if len(before) == 1 else "john.smith"] += 1
        else:
            votes["jsmith" if len(local) <= 8 else "johnsmith"] += 1
    best = max(votes, key=lambda k: votes[k])
    return best if votes[best] > 0 else None


def _probe_pattern(domain: str, log_fn=None) -> str:
    """
    Send a small O365 probe to determine the email naming convention used
    by this organisation. Tests _PROBE_NAMES in all 4 formats and returns
    the pattern with the most confirmed hits.
    """
    scores: dict[str, int] = {p: 0 for p in _PATTERN_FORMATS}

    if log_fn:
        log_fn(f"Probing naming pattern — testing {len(_PROBE_NAMES)} names × {len(_PATTERN_FORMATS)} formats …")

    for first, last in _PROBE_NAMES:
        for pattern, fmt_fn in _PATTERN_FORMATS.items():
            username = fmt_fn(first, last)
            email = f"{username}@{domain}"
            if _check_o365(email):
                scores[pattern] += 1
                if log_fn:
                    log_fn(f"  [probe hit] {email}  → pattern={pattern}")
            time.sleep(0.1)

    best_score = max(scores.values())
    if best_score == 0:
        if log_fn:
            log_fn("No probe hits — defaulting to jsmith pattern")
        return "jsmith"

    winner = max(scores, key=lambda k: scores[k])
    if log_fn:
        log_fn(f"Pattern scores: {scores}")
        log_fn(f"Selected pattern: {winner}  (score={scores[winner]})")
    return winner

# Ensure Go binaries and common tool paths are discoverable
_EXTRA_PATHS = [
    os.path.expanduser("~/go/bin"),
    "/usr/local/bin",
    "/usr/local/go/bin",
]
os.environ["PATH"] = os.pathsep.join(
    _EXTRA_PATHS + [p for p in os.environ.get("PATH", "").split(os.pathsep) if p not in _EXTRA_PATHS]
)


class ToolRunner:
    def __init__(self, scan_id: str, q: Queue, cancel_event=None):
        self.scan_id = scan_id
        self.q = q
        self._cancel = cancel_event  # threading.Event — set() to abort

    @property
    def cancelled(self) -> bool:
        return self._cancel is not None and self._cancel.is_set()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log(self, tool: str, msg: str):
        self.q.put({"type": "log", "tool": tool, "msg": msg})

    def _result(self, tool: str, data: dict):
        self.q.put({"type": "result", "tool": tool, "data": data})

    def _error(self, tool: str, msg: str):
        self.q.put({"type": "error", "tool": tool, "msg": msg})

    def _is_installed(self, cmd: str) -> bool:
        return shutil.which(cmd) is not None

    def _run(self, cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
        """Run a subprocess and return (stdout, stderr, returncode).
        If cancelled, kills the process and returns early."""
        if self.cancelled:
            return "", "Cancelled", -2
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # Poll with cancel check instead of blocking wait
            deadline = time.time() + timeout
            while proc.poll() is None:
                if self.cancelled:
                    proc.kill()
                    proc.wait(timeout=3)
                    return "", "Cancelled", -2
                if time.time() > deadline:
                    proc.kill()
                    proc.wait(timeout=3)
                    return "", "Timed out", -1
                time.sleep(0.3)
            stdout = proc.stdout.read() if proc.stdout else ""
            stderr = proc.stderr.read() if proc.stderr else ""
            return stdout, stderr, proc.returncode
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", -1
        except Exception as e:
            return "", str(e), -1

    # ------------------------------------------------------------------
    # Web scraper — extract employees from company website
    # ------------------------------------------------------------------

    def run_web_scrape(self, url: str) -> dict:
        import web_scraper as ws
        tool = "web_scrape"
        self._log(tool, f"Crawling: {url}")
        result = ws.scrape(url, log_fn=lambda m: self._log(tool, m))
        if "error" in result:
            self._error(tool, result["error"])
        else:
            self._log(tool, f"People: {len(result['people'])} | Emails: {len(result['emails_found'])} | Pages: {len(result['pages_crawled'])}")
            self._result(tool, result)
        return result

    # ------------------------------------------------------------------
    # Sherlock — username across social platforms
    # ------------------------------------------------------------------

    def run_sherlock(self, username: str) -> dict:
        tool = "sherlock"
        self._log(tool, f"Scanning username: {username}")

        if not self._is_installed("sherlock"):
            self._error(tool, "sherlock not installed. Run: pip install sherlock-project")
            return {"error": "not installed", "profiles": []}

        cmd = ["sherlock", username, "--print-found", "--no-color", "--no-txt", "--timeout", "10", "--local"]
        self._log(tool, f"Running: {' '.join(cmd)}")

        profiles = []
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                self._log(tool, line)
                m = re.match(r"\[\+\]\s+(.+?):\s+(https?://\S+)", line)
                if m:
                    profiles.append({"site": m.group(1), "url": m.group(2), "status": "found"})
            proc.wait(timeout=120)
            stderr = proc.stderr.read().strip()
            if stderr:
                self._log(tool, f"stderr: {stderr[:500]}")
            self._log(tool, f"Exit code: {proc.returncode}")
        except subprocess.TimeoutExpired:
            proc.kill()
            self._error(tool, "Sherlock timed out after 120s")
        except Exception as e:
            self._error(tool, f"Sherlock error: {e}")

        self._log(tool, f"Found {len(profiles)} profiles")
        result = {"username": username, "profiles": profiles, "count": len(profiles)}
        self._result(tool, result)
        return result

    # ------------------------------------------------------------------
    # Holehe — email → registered accounts
    # ------------------------------------------------------------------

    def run_holehe(self, email: str) -> dict:
        tool = "holehe"
        self._log(tool, f"Checking email: {email}")

        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            self._error(tool, f"'{email}' is not a valid email address — skipping")
            return {"error": "invalid email", "accounts": []}

        if not self._is_installed("holehe"):
            self._error(tool, "holehe not installed. Run: pip install holehe")
            return {"error": "not installed", "accounts": []}

        stdout, stderr, code = self._run(["holehe", email, "--no-color"], timeout=180)

        accounts = []
        not_found = []
        for line in stdout.splitlines():
            line = line.strip()
            found = re.match(r"\[✔\]\s+(.+)", line) or re.match(r"\[\+\]\s+(.+)", line)
            if found:
                accounts.append(found.group(1).strip())
            miss = re.match(r"\[✘\]\s+(.+)", line) or re.match(r"\[-\]\s+(.+)", line)
            if miss:
                not_found.append(miss.group(1).strip())

        self._log(tool, f"Found on {len(accounts)} sites")
        result = {
            "email": email,
            "accounts": accounts,
            "not_found": not_found,
            "count": len(accounts),
        }
        self._result(tool, result)
        return result

    # ------------------------------------------------------------------
    # theHarvester — emails, subdomains, IPs from a domain
    # ------------------------------------------------------------------

    def run_theharvester(self, domain: str) -> dict:
        tool = "theharvester"
        self._log(tool, f"Harvesting domain: {domain}")

        cmd = "theHarvester"
        if not self._is_installed(cmd):
            self._error(tool, "theHarvester not installed. See: github.com/laramies/theHarvester")
            return {"error": "not installed", "emails": [], "hosts": [], "ips": []}

        # Only the 3 fastest no-key sources — rest are too slow for live UI
        sources = "crtsh,hackertarget,rapiddns"
        self._log(tool, f"Sources: {sources}")
        self._log(tool, "Running… (up to 45s)")

        emails, hosts, ips = [], [], []
        stdout_lines = []

        with tempfile.TemporaryDirectory() as tmpdir:
            out_base = os.path.join(tmpdir, "harvester")
            try:
                proc = subprocess.Popen(
                    [cmd, "-d", domain, "-b", sources, "-l", "200", "-f", out_base],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                try:
                    for line in proc.stdout:
                        line = line.rstrip()
                        if line:
                            self._log(tool, line)
                            stdout_lines.append(line)
                    proc.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    self._log(tool, "theHarvester timed out after 45s — using partial results")
            except Exception as e:
                self._error(tool, f"theHarvester error: {e}")

            # Try JSON output first
            json_file = out_base + ".json"
            if os.path.exists(json_file):
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                    emails = list(set(data.get("emails", [])))
                    hosts  = list(set(data.get("hosts", [])))
                    ips    = list(set(data.get("ips", [])))
                except Exception:
                    pass

            # Fallback: parse streamed stdout
            if not emails and not hosts:
                emails, hosts, ips = _parse_harvester_stdout("\n".join(stdout_lines))

        self._log(tool, f"Emails: {len(emails)} | Hosts: {len(hosts)} | IPs: {len(ips)}")
        result = {
            "domain": domain,
            "emails": sorted(emails),
            "hosts": sorted(hosts),
            "ips": sorted(ips),
        }
        self._result(tool, result)
        return result

    # ------------------------------------------------------------------
    # Subfinder — passive subdomain enumeration
    # ------------------------------------------------------------------

    def run_subfinder(self, domain: str) -> dict:
        tool = "subfinder"
        self._log(tool, f"Enumerating subdomains for: {domain}")

        if not self._is_installed("subfinder"):
            self._error(tool, "subfinder not installed. See: github.com/projectdiscovery/subfinder")
            return {"error": "not installed", "subdomains": []}

        stdout, stderr, code = self._run(
            ["subfinder", "-d", domain, "-silent", "-json"],
            timeout=180,
        )

        subdomains = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                subdomains.append({"host": obj.get("host", ""), "source": obj.get("source", "")})
            except json.JSONDecodeError:
                if line:
                    subdomains.append({"host": line, "source": "unknown"})

        # Deduplicate by host
        seen = set()
        unique = []
        for s in subdomains:
            if s["host"] not in seen:
                seen.add(s["host"])
                unique.append(s)

        self._log(tool, f"Found {len(unique)} unique subdomains")
        result = {"domain": domain, "subdomains": unique, "count": len(unique)}
        self._result(tool, result)
        return result

    # ------------------------------------------------------------------
    # Amass — attack surface mapping
    # ------------------------------------------------------------------

    def run_amass(self, domain: str) -> dict:
        tool = "amass"
        self._log(tool, f"Running Amass passive enum for: {domain} (timeout: 60s)")

        if not self._is_installed("amass"):
            self._error(tool, "amass not installed. See: github.com/owasp-amass/amass")
            return {"error": "not installed", "subdomains": []}

        subdomains = []
        try:
            proc = subprocess.Popen(
                ["amass", "enum", "-passive", "-d", domain, "-timeout", "1"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            try:
                for line in proc.stdout:
                    line = line.strip()
                    if line:
                        subdomains.append(line)
                        self._log(tool, line)
                proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                proc.kill()
                self._log(tool, f"Amass timed out — using {len(subdomains)} partial results")
        except Exception as e:
            self._error(tool, f"Amass error: {e}")

        subdomains = list(set(subdomains))
        self._log(tool, f"Found {len(subdomains)} subdomains")
        result = {"domain": domain, "subdomains": subdomains, "count": len(subdomains)}
        self._result(tool, result)
        return result

    # ------------------------------------------------------------------
    # GitHub dork — search for company/person on GitHub
    # ------------------------------------------------------------------

    def run_github_dork(self, query: str) -> dict:
        tool = "github"
        self._log(tool, f"GitHub search: {query}")

        # Uses GitHub CLI (gh) if available
        if not self._is_installed("gh"):
            self._error(tool, "GitHub CLI (gh) not installed. See: cli.github.com")
            return {"error": "not installed", "repos": [], "users": []}

        # Search repos
        stdout_r, stderr_r, code_r = self._run(
            ["gh", "search", "repos", query, "--limit", "20", "--json",
             "name,fullName,description,url,stargazersCount,updatedAt"],
            timeout=30,
        )
        self._log(tool, f"Repos search exit code: {code_r}")
        if stderr_r.strip():
            self._log(tool, f"Repos stderr: {stderr_r.strip()[:300]}")
        self._log(tool, f"Repos stdout: {stdout_r.strip()[:300] or '(empty)'}")
        repos = []
        try:
            repos = json.loads(stdout_r) if stdout_r.strip() else []
        except Exception as e:
            self._log(tool, f"Repos JSON parse error: {e}")

        # Search users via GitHub API
        import urllib.parse
        encoded = urllib.parse.quote(query)
        stdout_u, stderr_u, code_u = self._run(
            ["gh", "api", f"search/users?q={encoded}&per_page=10"],
            timeout=30,
        )
        self._log(tool, f"Users search exit code: {code_u}")
        if stderr_u.strip():
            self._log(tool, f"Users stderr: {stderr_u.strip()[:300]}")
        self._log(tool, f"Users stdout: {stdout_u.strip()[:300] or '(empty)'}")
        users = []
        try:
            data = json.loads(stdout_u) if stdout_u.strip() else {}
            for item in data.get("items", []):
                users.append({
                    "login": item.get("login", ""),
                    "url": item.get("html_url", ""),
                    "name": item.get("login", ""),
                })
        except Exception as e:
            self._log(tool, f"Users JSON parse error: {e}")

        self._log(tool, f"Repos: {len(repos)} | Users: {len(users)}")
        result = {"query": query, "repos": repos, "users": users}
        self._result(tool, result)
        return result


    # ------------------------------------------------------------------
    # Maigret — search person name / username across 2500+ sites
    # ------------------------------------------------------------------

    def run_maigret(self, name: str) -> dict:
        tool = "maigret"
        self._log(tool, f"Maigret search: {name}")

        if not self._is_installed("maigret"):
            self._error(tool, "maigret not installed. pip install maigret")
            return {"error": "not installed", "accounts": []}

        # Build username variants from name: "John Doe" → jdoe, john.doe, etc.
        parts = name.lower().split()
        queries = set()
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            fi = first[0]
            queries.update([
                f"{fi}{last}",          # jdoe
                f"{first}.{last}",      # john.doe
                f"{first}{last}",       # johndoe
                f"{first}_{last}",      # john_doe
                f"{fi}.{last}",         # j.doe
                f"{last}{fi}",          # doej
            ])
        else:
            queries.add(parts[0])

        all_accounts = []
        tmpdir = tempfile.mkdtemp(prefix="maigret_")

        for q in list(queries)[:4]:  # cap to avoid long runtime
            self._log(tool, f"  Checking username: {q}")
            stdout, stderr, code = self._run(
                ["maigret", q,
                 "--no-color", "--no-progressbar",
                 "--timeout", "8",
                 "--top-sites", "50",
                 "-J", "simple",
                 "--folderoutput", tmpdir],
                timeout=45,
            )

            # Parse JSON output if available
            json_file = os.path.join(tmpdir, f"report_{q}_simple.json")
            if os.path.exists(json_file):
                try:
                    with open(json_file) as f:
                        data = json.load(f)
                    for site_name, info in data.items():
                        if isinstance(info, dict) and info.get("status"):
                            status = info["status"].get("status", "")
                            if status == "Claimed":
                                all_accounts.append({
                                    "username": q,
                                    "site": site_name,
                                    "url": info.get("url_user", ""),
                                    "status": "claimed",
                                })
                except Exception as e:
                    self._log(tool, f"  JSON parse error: {e}")

            # Fallback: parse stdout for found accounts
            if not all_accounts:
                for line in stdout.splitlines():
                    line = line.strip()
                    if "http" in line and ("Claimed" in line or "[+]" in line):
                        url_match = re.search(r'(https?://\S+)', line)
                        if url_match:
                            all_accounts.append({
                                "username": q,
                                "site": "",
                                "url": url_match.group(1),
                                "status": "claimed",
                            })

        # Cleanup tmp
        import shutil as _shutil
        _shutil.rmtree(tmpdir, ignore_errors=True)

        # Deduplicate by URL
        seen_urls = set()
        deduped = []
        for a in all_accounts:
            if a["url"] not in seen_urls:
                seen_urls.add(a["url"])
                deduped.append(a)

        self._log(tool, f"Maigret: {len(deduped)} accounts found across {len(queries)} username variants")
        result = {"name": name, "usernames_checked": list(queries), "accounts": deduped, "count": len(deduped)}
        self._result(tool, result)
        return result


    # ------------------------------------------------------------------
    # Social Analyzer — search by name across 900+ social platforms
    # ------------------------------------------------------------------

    def run_social_analyzer(self, name: str) -> dict:
        tool = "social_analyzer"
        self._log(tool, f"Social Analyzer: {name}")

        if not self._is_installed("social-analyzer"):
            self._error(tool, "social-analyzer not installed. pip install social-analyzer")
            return {"error": "not installed", "profiles": []}

        # social-analyzer searches by username across social platforms
        parts = name.lower().split()
        queries = set()
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            queries.update([
                f"{first}{last}",
                f"{first}.{last}",
                f"{first[0]}{last}",
                f"{first}_{last}",
            ])
        else:
            queries.add(parts[0])

        all_profiles = []

        for q in list(queries)[:3]:
            self._log(tool, f"  Checking: {q}")
            stdout, stderr, code = self._run(
                ["social-analyzer",
                 "--username", q,
                 "--mode", "fast",
                 "--output", "json",
                 "--silent"],
                timeout=60,
            )

            try:
                data = json.loads(stdout) if stdout.strip() else {}
                detected = data.get("detected", [])
                for site in detected:
                    all_profiles.append({
                        "username": q,
                        "site": site.get("name", ""),
                        "url": site.get("link", ""),
                        "title": site.get("title", ""),
                    })
            except Exception:
                # Fallback: parse stdout for URLs
                for line in stdout.splitlines():
                    url_match = re.search(r'(https?://\S+)', line)
                    if url_match:
                        all_profiles.append({
                            "username": q,
                            "site": "",
                            "url": url_match.group(1),
                            "title": "",
                        })

        self._log(tool, f"Social Analyzer: {len(all_profiles)} profiles found")
        result = {"name": name, "profiles": all_profiles, "count": len(all_profiles)}
        self._result(tool, result)
        return result


    # ------------------------------------------------------------------
    # Google Dorking — search for person or company name via Google
    # ------------------------------------------------------------------

    def run_google_dork(self, query: str, query_type: str = "person") -> dict:
        tool = "google_dork"
        self._log(tool, f"Google dork ({query_type}): {query}")

        dorks = []
        if query_type == "person":
            dorks = [
                f'"{query}" site:linkedin.com',
                f'"{query}" site:twitter.com OR site:x.com',
                f'"{query}" site:facebook.com',
                f'"{query}" resume OR CV filetype:pdf',
                f'"{query}" email OR contact',
                f'intitle:"{query}" -site:pinterest.com',
            ]
        elif query_type == "company":
            dorks = [
                f'"{query}" site:linkedin.com/company',
                f'"{query}" employees OR team OR staff',
                f'"{query}" site:crunchbase.com OR site:bloomberg.com',
                f'"{query}" filetype:pdf',
                f'"{query}" org chart OR management team',
                f'"{query}" glassdoor OR indeed',
                f'"{query}" annual report OR investor relations',
            ]

        results_list = []
        for dork in dorks:
            encoded = urllib.parse.quote(dork)
            search_url = f"https://www.google.com/search?q={encoded}&num=5"
            self._log(tool, f"  Dork: {dork}")

            try:
                req = urllib.request.Request(search_url, headers={
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/124.0.0.0 Safari/537.36",
                })
                ctx = __import__('ssl').create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = __import__('ssl').CERT_NONE
                with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                    html = resp.read().decode("utf-8", errors="replace")

                # Extract result URLs from Google HTML
                urls = re.findall(r'href="(https?://(?!www\.google\.com)[^"&]+)"', html)
                # Filter noise
                clean = [u for u in urls if not any(x in u for x in [
                    'google.com', 'gstatic.com', 'googleapis.com',
                    'accounts.google', 'support.google', 'maps.google',
                ])][:5]

                results_list.append({
                    "dork": dork,
                    "search_url": search_url,
                    "results": clean,
                })
            except Exception as e:
                results_list.append({
                    "dork": dork,
                    "search_url": search_url,
                    "results": [],
                    "error": str(e),
                })

            time.sleep(1.5)  # Polite delay between searches

        total_urls = sum(len(r["results"]) for r in results_list)
        self._log(tool, f"Google dorking: {total_urls} results from {len(dorks)} dorks")
        result = {"query": query, "type": query_type, "dorks": results_list, "total_results": total_urls}
        self._result(tool, result)
        return result


    # ------------------------------------------------------------------
    # Company search — LinkedIn, Crunchbase, and public registries
    # ------------------------------------------------------------------

    def run_company_search(self, company: str) -> dict:
        tool = "company_search"
        self._log(tool, f"Company search: {company}")

        info = {
            "company": company,
            "linkedin": [],
            "crunchbase": [],
            "registries": [],
            "news": [],
        }

        encoded = urllib.parse.quote(company)

        # Search public company data sources
        searches = [
            ("LinkedIn",     f"https://www.google.com/search?q={urllib.parse.quote(company + ' site:linkedin.com/company')}&num=5"),
            ("Crunchbase",   f"https://www.google.com/search?q={urllib.parse.quote(company + ' site:crunchbase.com')}&num=5"),
            ("OpenCorporates", f"https://api.opencorporates.com/v0.4/companies/search?q={encoded}&per_page=5"),
            ("News",         f"https://www.google.com/search?q={urllib.parse.quote(company + ' news OR press release')}&num=10&tbm=nws"),
        ]

        for source_name, url in searches:
            self._log(tool, f"  Searching {source_name}...")
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                                  "AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
                })
                ctx = __import__('ssl').create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = __import__('ssl').CERT_NONE
                with urllib.request.urlopen(req, context=ctx, timeout=12) as resp:
                    body = resp.read().decode("utf-8", errors="replace")

                if source_name == "OpenCorporates":
                    try:
                        data = json.loads(body)
                        for co in data.get("results", {}).get("companies", []):
                            c = co.get("company", {})
                            info["registries"].append({
                                "name": c.get("name", ""),
                                "jurisdiction": c.get("jurisdiction_code", ""),
                                "status": c.get("current_status", ""),
                                "incorporation_date": c.get("incorporation_date", ""),
                                "url": c.get("opencorporates_url", ""),
                            })
                    except Exception:
                        pass
                else:
                    urls = re.findall(r'href="(https?://(?!www\.google\.com)[^"&]+)"', body)
                    clean = [u for u in urls if not any(x in u for x in [
                        'google.com', 'gstatic.com', 'googleapis.com',
                        'accounts.google', 'support.google',
                    ])][:5]
                    key = source_name.lower()
                    if key in info:
                        info[key] = clean
                    else:
                        info["news"] = clean

            except Exception as e:
                self._log(tool, f"  {source_name} error: {e}")

            time.sleep(1)

        total = len(info["linkedin"]) + len(info["crunchbase"]) + len(info["registries"]) + len(info["news"])
        self._log(tool, f"Company search: {total} results across 4 sources")
        result = info
        self._result(tool, result)
        return result


    # ------------------------------------------------------------------
    # Email Enumeration — validate usernames@domain via O365 API
    # Uses statistically-likely-usernames lists; detects naming pattern
    # from any emails already found by theHarvester.
    # ------------------------------------------------------------------

    def run_email_enum(self, domain: str, known_emails: list[str] = None, limit: int = 1500) -> dict:
        tool = "email_enum"
        self._log(tool, f"Email enumeration for: {domain}")

        # 1. Try to infer pattern from already-known emails
        pattern = _infer_pattern_from_emails(known_emails or [])
        if pattern:
            self._log(tool, f"Pattern inferred from known emails: {pattern}")
        else:
            # 2. No known emails — run a live O365 probe to detect the pattern
            pattern = _probe_pattern(domain, log_fn=lambda m: self._log(tool, m))

        self._log(tool, f"Using pattern: {pattern}")

        # 2b. Catch-all sanity check — test a random impossible username before enumerating
        import random as _random
        import string as _string
        canary = ''.join(_random.choices(_string.ascii_lowercase + _string.digits, k=14))
        canary_email = f"{canary}@{domain}"
        self._log(tool, f"Catch-all check: {canary_email}")
        try:
            if _check_o365(canary_email):
                self._error(tool, (
                    f"Catch-all detected — {domain} accepts all addresses. "
                    "Enumeration results would be unreliable. Aborting."
                ))
                return {"error": "catch-all", "domain": domain, "valid": [], "checked": 0, "count": 0}
            self._log(tool, "Catch-all check passed — domain rejects unknown users")
        except Exception as e:
            self._log(tool, f"Catch-all check failed ({e}) — proceeding anyway")

        # 3. Load wordlist
        wordlist_path = _USERNAME_LISTS.get(pattern, _USERNAME_LISTS["jsmith"])
        if not os.path.exists(wordlist_path) or os.path.getsize(wordlist_path) == 0:
            wordlist_path = _USERNAME_LISTS["jsmith"]  # fallback
        if not os.path.exists(wordlist_path):
            self._error(tool, f"Wordlist not found: {wordlist_path}")
            return {"error": "wordlist missing", "valid": [], "checked": 0}

        with open(wordlist_path) as f:
            usernames = [line.strip() for line in f if line.strip()][:limit]

        self._log(tool, f"Loaded {len(usernames)} usernames from {os.path.basename(wordlist_path)}")
        self._log(tool, f"Validating against O365 API — this may take a few minutes…")

        # 3. Validate each username@domain via Microsoft GetCredentialType API
        valid = []
        checked = 0
        errors = 0

        for username in usernames:
            email = f"{username}@{domain}"
            try:
                if _check_o365(email):
                    valid.append(email)
                    self._log(tool, f"[+] VALID: {email}")
                checked += 1
                errors = 0
                if checked % 100 == 0:
                    self._log(tool, f"Progress: {checked}/{len(usernames)} checked | {len(valid)} found")
                time.sleep(0.15)
            except Exception as e:
                errors += 1
                if errors >= 5:
                    self._error(tool, f"Too many errors — stopping early at {checked}: {e}")
                    break
                time.sleep(0.5)

        self._log(tool, f"Done. Checked: {checked} | Valid: {len(valid)}")
        result = {
            "domain": domain,
            "pattern": pattern,
            "wordlist": os.path.basename(wordlist_path),
            "checked": checked,
            "valid": valid,
            "count": len(valid),
        }
        self._result(tool, result)
        return result

    # ------------------------------------------------------------------
    # WhatsMyName — username across 600+ sites (complements Sherlock)
    # ------------------------------------------------------------------

    def run_whatsmyname(self, username: str) -> dict:
        """Uses maigret (WhatsMyName-compatible) for broad username search."""
        tool = "whatsmyname"
        self._log(tool, f"Checking username via maigret: {username}")

        if not self._is_installed("maigret"):
            self._error(tool, "maigret not installed. Run: pip install maigret")
            return {"error": "not installed", "profiles": []}

        with tempfile.TemporaryDirectory() as tmpdir:
            out_json = os.path.join(tmpdir, f"{username}.json")
            stdout, stderr, code = self._run(
                ["maigret", username, "--json", out_json, "--no-progressbar", "--timeout", "10"],
                timeout=180,
            )

            profiles = []
            if os.path.exists(out_json):
                try:
                    with open(out_json) as f:
                        data = json.load(f)
                    for site, info in data.items():
                        if isinstance(info, dict) and info.get("status", {}).get("status") == "Claimed":
                            profiles.append({
                                "site": site,
                                "url": info.get("url_user", info.get("url", "")),
                            })
                except Exception as e:
                    self._log(tool, f"JSON parse error: {e}")

            if not profiles:
                # Fallback: parse stdout for [+] lines
                for line in (stdout + stderr).splitlines():
                    m = re.search(r"\[\+\]\s+(.+?):\s+(https?://\S+)", line)
                    if m:
                        profiles.append({"site": m.group(1).strip(), "url": m.group(2).strip()})

        self._log(tool, f"Found {len(profiles)} profiles")
        result = {"username": username, "profiles": profiles, "count": len(profiles)}
        self._result(tool, result)
        return result

    # ------------------------------------------------------------------
    # GitFive — deep GitHub user OSINT from username
    # ------------------------------------------------------------------

    def run_gitfive(self, username: str) -> dict:
        tool = "gitfive"
        self._log(tool, f"GitFive scanning: {username}")

        if not self._is_installed("gitfive"):
            self._error(tool, "gitfive not installed. Run: pip install gitfive && gitfive init")
            return {"error": "not installed"}

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, "gitfive_out.json")
            stdout, stderr, code = self._run(
                ["gitfive", "user", username, "--json", out_file],
                timeout=120,
            )
            if stderr and "not logged" in stderr.lower():
                self._error(tool, "gitfive not authenticated. Run: gitfive init")
                return {"error": "not authenticated"}

            data = {}
            if os.path.exists(out_file):
                try:
                    with open(out_file) as f:
                        data = json.load(f)
                except Exception:
                    pass

            if not data:
                # Try parsing stdout as JSON
                try:
                    data = json.loads(stdout)
                except Exception:
                    pass

        emails = data.get("possible_emails", data.get("emails", []))
        repos = data.get("repos", [])
        orgs = data.get("orgs", data.get("organizations", []))
        profile = data.get("profile", {})

        self._log(tool, f"Email guesses: {len(emails)} | Repos: {len(repos)} | Orgs: {len(orgs)}")
        result = {
            "username": username,
            "profile": profile,
            "possible_emails": emails if isinstance(emails, list) else list(emails),
            "repos": repos[:30],
            "orgs": orgs,
        }
        self._result(tool, result)
        return result

    # ------------------------------------------------------------------
    # GHunt — Google account OSINT from email (needs ghunt login first)
    # ------------------------------------------------------------------

    def run_ghunt(self, email: str) -> dict:
        tool = "ghunt"
        self._log(tool, f"GHunt lookup for: {email}")

        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            self._error(tool, f"'{email}' is not a valid email address — skipping")
            return {"error": "invalid email"}

        if not self._is_installed("ghunt"):
            self._error(tool, "ghunt not installed. Run: pip install ghunt")
            return {"error": "not installed"}

        with tempfile.TemporaryDirectory() as tmpdir:
            out_json = os.path.join(tmpdir, "ghunt_out.json")
            stdout, stderr, code = self._run(
                ["ghunt", "email", email, "--json", out_json],
                timeout=60,
            )

            if "not logged" in (stdout + stderr).lower() or "login" in (stdout + stderr).lower():
                self._error(tool, "GHunt not authenticated. Run: ghunt login")
                return {"error": "not authenticated"}

            data = {}
            if os.path.exists(out_json):
                try:
                    with open(out_json) as f:
                        data = json.load(f)
                except Exception as e:
                    self._log(tool, f"JSON parse error: {e}")

        if not data:
            self._log(tool, "No data returned")
            result = {"email": email, "found": False}
        else:
            result = {
                "email": email,
                "found": True,
                "name": data.get("name", ""),
                "profile_pic": data.get("profile_pic", ""),
                "google_id": data.get("google_id", ""),
                "last_edit": data.get("last_edit", ""),
                "maps": data.get("maps", {}),
                "calendar": data.get("calendar", {}),
                "services": data.get("services", []),
                "raw": data,
            }
            self._log(tool, f"Found: {result['name']} | Services: {len(result['services'])}")

        self._result(tool, result)
        return result

    # ------------------------------------------------------------------
    # EmailRep.io — email reputation and risk score (free HTTP API)
    # ------------------------------------------------------------------

    def run_emailrep(self, email: str) -> dict:
        tool = "emailrep"
        self._log(tool, f"Checking reputation for: {email}")

        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            self._error(tool, f"'{email}' is not a valid email address — skipping")
            return {"error": "invalid email", "email": email}

        api_key = os.environ.get("EMAILREP_KEY", "")
        headers = {"User-Agent": "RedBalance-OSINT/1.0"}
        if api_key:
            headers["Key"] = api_key

        try:
            req = urllib.request.Request(
                f"https://emailrep.io/{urllib.parse.quote(email)}",
                headers=headers,
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = json.loads(resp.read())

            details = raw.get("details", {})
            result = {
                "email": email,
                "reputation": raw.get("reputation", "unknown"),
                "suspicious": raw.get("suspicious", False),
                "references": raw.get("references", 0),
                "blacklisted": details.get("blacklisted", False),
                "malicious_activity": details.get("malicious_activity", False),
                "credentials_leaked": details.get("credentials_leaked", False),
                "data_breach": details.get("data_breach", False),
                "profiles": details.get("profiles", []),
                "sport": details.get("sport", ""),
                "first_seen": details.get("first_seen", ""),
                "last_seen": details.get("last_seen", ""),
                "domain_exists": details.get("domain_exists", True),
                "disposable": details.get("disposable", False),
                "free_provider": details.get("free_provider", False),
            }
            self._log(tool, f"Reputation: {result['reputation']} | Suspicious: {result['suspicious']}")
            self._result(tool, result)
            return result

        except urllib.error.HTTPError as e:
            self._error(tool, f"EmailRep HTTP {e.code}: {e.reason}")
            return {"error": f"HTTP {e.code}", "email": email}
        except Exception as e:
            self._error(tool, f"EmailRep error: {e}")
            return {"error": str(e), "email": email}

    # ------------------------------------------------------------------
    # HaveIBeenPwned — breach data for an email (needs HIBP_API_KEY)
    # ------------------------------------------------------------------

    def run_haveibeenpwned(self, email: str) -> dict:
        tool = "hibp"
        self._log(tool, f"Checking breach data for: {email}")

        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            self._error(tool, f"'{email}' is not a valid email address — skipping")
            return {"error": "invalid email", "breaches": [], "pastes": []}

        api_key = os.environ.get("HIBP_API_KEY", "")
        if not api_key:
            self._error(tool, "HIBP_API_KEY not set. Get a key at haveibeenpwned.com/API/Key")
            return {"error": "no API key", "breaches": [], "pastes": []}

        breaches = []
        pastes = []

        # Breach check
        try:
            req = urllib.request.Request(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false",
                headers={
                    "hibp-api-key": api_key,
                    "user-agent": "RedBalance-OSINT/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            breaches = [
                {
                    "name": b.get("Name", ""),
                    "domain": b.get("Domain", ""),
                    "date": b.get("BreachDate", ""),
                    "count": b.get("PwnCount", 0),
                    "data_classes": b.get("DataClasses", []),
                }
                for b in data
            ]
        except urllib.error.HTTPError as e:
            if e.code == 404:
                self._log(tool, "No breaches found")
            else:
                self._error(tool, f"HIBP breaches HTTP {e.code}")
        except Exception as e:
            self._error(tool, f"HIBP breaches error: {e}")

        # Paste check
        try:
            req2 = urllib.request.Request(
                f"https://haveibeenpwned.com/api/v3/pasteaccount/{urllib.parse.quote(email)}",
                headers={
                    "hibp-api-key": api_key,
                    "user-agent": "RedBalance-OSINT/1.0",
                },
            )
            with urllib.request.urlopen(req2, timeout=15) as resp2:
                data2 = json.loads(resp2.read())
            pastes = [
                {
                    "source": p.get("Source", ""),
                    "title": p.get("Title", ""),
                    "date": p.get("Date", ""),
                    "email_count": p.get("EmailCount", 0),
                }
                for p in data2
            ]
        except urllib.error.HTTPError as e:
            if e.code != 404:
                self._error(tool, f"HIBP pastes HTTP {e.code}")
        except Exception as e:
            self._error(tool, f"HIBP pastes error: {e}")

        self._log(tool, f"Breaches: {len(breaches)} | Pastes: {len(pastes)}")
        result = {"email": email, "breaches": breaches, "pastes": pastes,
                  "breach_count": len(breaches), "paste_count": len(pastes)}
        self._result(tool, result)
        return result

    # ------------------------------------------------------------------
    # Shodan — internet exposure for a domain/IP (needs SHODAN_API_KEY)
    # ------------------------------------------------------------------

    def run_shodan(self, domain: str) -> dict:
        tool = "shodan"
        self._log(tool, f"Shodan search for: {domain}")

        api_key = os.environ.get("SHODAN_API_KEY", "")
        if not api_key:
            self._error(tool, "SHODAN_API_KEY not set. Get a free key at shodan.io")
            return {"error": "no API key", "results": []}

        try:
            import shodan as shodan_lib
        except ImportError:
            self._error(tool, "shodan library not installed. Run: pip install shodan")
            return {"error": "not installed", "results": []}

        try:
            api = shodan_lib.Shodan(api_key)
            self._log(tool, "Searching hosts by hostname...")
            search = api.search(f"hostname:{domain}", limit=50)
            results = []
            for match in search.get("matches", []):
                vulns = list(match.get("vulns", {}).keys()) if match.get("vulns") else []
                results.append({
                    "ip": match.get("ip_str", ""),
                    "port": match.get("port", ""),
                    "org": match.get("org", ""),
                    "hostnames": ", ".join(match.get("hostnames", [])),
                    "product": match.get("product", ""),
                    "version": match.get("version", ""),
                    "os": match.get("os", ""),
                    "vulns": vulns,
                    "country": match.get("location", {}).get("country_name", ""),
                })
            self._log(tool, f"Found {len(results)} hosts (total: {search.get('total', 0)})")
            result = {
                "domain": domain,
                "results": results,
                "count": len(results),
                "total": search.get("total", 0),
            }
            self._result(tool, result)
            return result

        except shodan_lib.APIError as e:
            self._error(tool, f"Shodan API error: {e}")
            return {"error": str(e), "results": []}
        except Exception as e:
            self._error(tool, f"Shodan error: {e}")
            return {"error": str(e), "results": []}

    # ------------------------------------------------------------------
    # Censys — certificate & host search (needs CENSYS_API_ID + SECRET)
    # ------------------------------------------------------------------

    def run_censys(self, domain: str) -> dict:
        tool = "censys"
        self._log(tool, f"Censys search for: {domain}")

        api_id = os.environ.get("CENSYS_API_ID", "")
        api_secret = os.environ.get("CENSYS_API_SECRET", "")
        if not api_id or not api_secret:
            self._error(tool, "CENSYS_API_ID / CENSYS_API_SECRET not set. Register at censys.io")
            return {"error": "no API key", "hosts": []}

        try:
            from censys.search import CensysHosts
        except ImportError:
            self._error(tool, "censys library not installed. Run: pip install censys")
            return {"error": "not installed", "hosts": []}

        try:
            h = CensysHosts(api_id=api_id, api_secret=api_secret)
            query = f'services.tls.certificates.leaf_data.names: "{domain}"'
            self._log(tool, f"Query: {query}")

            hosts = []
            for page in h.search(query, per_page=50, pages=1):
                for host in page:
                    services = [
                        f"{s.get('port')}/{s.get('transport_protocol', 'TCP')}"
                        for s in host.get("services", [])
                    ]
                    hosts.append({
                        "ip": host.get("ip", ""),
                        "services": services,
                        "autonomous_system": host.get("autonomous_system", {}).get("name", ""),
                        "country": host.get("location", {}).get("country", ""),
                    })

            self._log(tool, f"Found {len(hosts)} hosts")
            result = {"domain": domain, "hosts": hosts, "count": len(hosts)}
            self._result(tool, result)
            return result

        except Exception as e:
            self._error(tool, f"Censys error: {e}")
            return {"error": str(e), "hosts": []}


# ------------------------------------------------------------------
# Standalone parser helpers
# ------------------------------------------------------------------

def _parse_harvester_stdout(stdout: str) -> tuple[list, list, list]:
    emails, hosts, ips = [], [], []
    section = None
    for line in stdout.splitlines():
        line = line.strip()
        if re.search(r"Emails found", line, re.I):
            section = "emails"
        elif re.search(r"Hosts found|Hostnames found", line, re.I):
            section = "hosts"
        elif re.search(r"IPs found", line, re.I):
            section = "ips"
        elif line.startswith("[*]") or line.startswith("[-]") or not line:
            continue
        else:
            if section == "emails" and "@" in line:
                emails.append(line)
            elif section == "hosts" and "." in line:
                hosts.append(line)
            elif section == "ips" and re.match(r"\d+\.\d+\.\d+\.\d+", line):
                ips.append(line)
    return list(set(emails)), list(set(hosts)), list(set(ips))


# ──────────────────────────────────────────────────────────────────────────────
# Face / Reverse Image Search — ToolRunner methods
# ──────────────────────────────────────────────────────────────────────────────

def _add_face_search_methods():
    """Attach reverse image search methods to ToolRunner (keeps class definition clean)."""

    def run_google_reverse_image(self, image_path: str) -> dict:
        """Upload image to Google Lens and parse results."""
        tool = "google_images"
        self._log(tool, "Uploading to Google Lens...")
        try:
            import base64
            with open(image_path, "rb") as f:
                img_data = f.read()
            # Use Google Lens upload endpoint
            boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="encoded_image"; filename="image.jpg"\r\n'
                f"Content-Type: image/jpeg\r\n\r\n"
            ).encode() + img_data + f"\r\n--{boundary}--\r\n".encode()

            req = urllib.request.Request(
                "https://lens.google.com/v3/upload?hl=en",
                data=body,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                redirect_url = resp.url
                html = resp.read().decode("utf-8", errors="replace")

            # Parse visual matches from response
            matches = []
            # Extract titles and URLs from the page
            import re as _re
            for m in _re.finditer(r'<a[^>]+href="(https?://[^"]+)"[^>]*>([^<]+)</a>', html):
                url, title = m.group(1), m.group(2).strip()
                if "google.com" in url or not title:
                    continue
                matches.append({"url": url, "title": title})

            self._log(tool, f"Found {len(matches)} visual matches")
            result = {"matches": matches[:30], "count": len(matches), "search_url": redirect_url}
            self._result(tool, result)
            return result
        except Exception as e:
            self._error(tool, f"Google Lens failed: {e}")
            return {"error": str(e), "matches": []}

    def run_yandex_reverse_image(self, image_path: str) -> dict:
        """Upload image to Yandex Images reverse search."""
        tool = "yandex_images"
        self._log(tool, "Uploading to Yandex Images...")
        try:
            with open(image_path, "rb") as f:
                img_data = f.read()
            boundary = "----YandexBoundary"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="upfile"; filename="image.jpg"\r\n'
                f"Content-Type: image/jpeg\r\n\r\n"
            ).encode() + img_data + f"\r\n--{boundary}--\r\n".encode()

            req = urllib.request.Request(
                "https://yandex.com/images/search?rpt=imageview&format=json",
                data=body,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                redirect_url = resp.url
                html = resp.read().decode("utf-8", errors="replace")

            matches = []
            import re as _re
            for m in _re.finditer(r'"url"\s*:\s*"(https?://[^"]+)".*?"title"\s*:\s*"([^"]*)"', html):
                url, title = m.group(1), m.group(2)
                if "yandex" not in url:
                    matches.append({"url": url, "title": title})

            self._log(tool, f"Found {len(matches)} results from Yandex")
            result = {"matches": matches[:30], "count": len(matches), "search_url": redirect_url}
            self._result(tool, result)
            return result
        except Exception as e:
            self._error(tool, f"Yandex reverse image failed: {e}")
            return {"error": str(e), "matches": []}

    def run_bing_reverse_image(self, image_path: str) -> dict:
        """Upload image to Bing Visual Search."""
        tool = "bing_images"
        self._log(tool, "Uploading to Bing Visual Search...")
        try:
            with open(image_path, "rb") as f:
                img_data = f.read()
            boundary = "----BingBoundary"
            body = (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="image"; filename="image.jpg"\r\n'
                f"Content-Type: image/jpeg\r\n\r\n"
            ).encode() + img_data + f"\r\n--{boundary}--\r\n".encode()

            req = urllib.request.Request(
                "https://www.bing.com/images/search?view=detailv2&iss=sbiupload&FORM=SBIHMP",
                data=body,
                headers={
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                redirect_url = resp.url
                html = resp.read().decode("utf-8", errors="replace")

            matches = []
            import re as _re
            for m in _re.finditer(r'<a[^>]+href="(https?://[^"]+)"[^>]*title="([^"]*)"', html):
                url, title = m.group(1), m.group(2).strip()
                if "bing.com" not in url and "microsoft.com" not in url and title:
                    matches.append({"url": url, "title": title})

            self._log(tool, f"Found {len(matches)} results from Bing")
            result = {"matches": matches[:30], "count": len(matches), "search_url": redirect_url}
            self._result(tool, result)
            return result
        except Exception as e:
            self._error(tool, f"Bing Visual Search failed: {e}")
            return {"error": str(e), "matches": []}

    def run_tineye(self, image_path: str) -> dict:
        """Search TinEye for reverse image matches."""
        tool = "tineye"
        self._log(tool, "Uploading to TinEye...")
        try:
            with open(image_path, "rb") as f:
                img_data = f.read()

            api_key = os.environ.get("TINEYE_API_KEY", "")

            if api_key:
                # Use TinEye API
                import base64
                payload = json.dumps({"image": base64.b64encode(img_data).decode()}).encode()
                req = urllib.request.Request(
                    "https://api.tineye.com/rest/search/",
                    data=payload,
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": api_key,
                    },
                )
            else:
                # Use free web upload
                boundary = "----TinEyeBoundary"
                body = (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="image"; filename="image.jpg"\r\n'
                    f"Content-Type: image/jpeg\r\n\r\n"
                ).encode() + img_data + f"\r\n--{boundary}--\r\n".encode()
                req = urllib.request.Request(
                    "https://tineye.com/search/",
                    data=body,
                    headers={
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    },
                    method="POST",
                )

            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read().decode("utf-8", errors="replace")

            matches = []
            import re as _re
            if api_key:
                try:
                    j = json.loads(data)
                    for m in j.get("results", {}).get("matches", []):
                        matches.append({
                            "url": m.get("backlinks", [{}])[0].get("url", ""),
                            "title": m.get("domain", ""),
                            "score": m.get("score", 0),
                        })
                except (json.JSONDecodeError, KeyError):
                    pass
            else:
                for m in _re.finditer(r'"url"\s*:\s*"(https?://[^"]+)"', data):
                    matches.append({"url": m.group(1), "title": ""})

            self._log(tool, f"Found {len(matches)} TinEye matches")
            result = {"matches": matches[:30], "count": len(matches)}
            self._result(tool, result)
            return result
        except Exception as e:
            self._error(tool, f"TinEye failed: {e}")
            return {"error": str(e), "matches": []}

    def run_pimeyes(self, image_path: str) -> dict:
        """Search PimEyes API (requires paid API key)."""
        tool = "pimeyes"
        api_key = os.environ.get("PIMEYES_API_KEY", "")
        if not api_key:
            self._log(tool, "PimEyes API key not configured — skipping")
            return {"error": "no API key", "matches": []}

        self._log(tool, "Searching PimEyes...")
        try:
            import base64
            with open(image_path, "rb") as f:
                img_b64 = base64.b64encode(f.read()).decode()

            payload = json.dumps({"image": f"data:image/jpeg;base64,{img_b64}"}).encode()
            req = urllib.request.Request(
                "https://pimeyes.com/api/search",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                    "User-Agent": "RedBalance-OSINT/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())

            matches = []
            for r in data.get("results", []):
                matches.append({
                    "url": r.get("url", ""),
                    "title": r.get("siteName", ""),
                    "thumbnail": r.get("thumbnailUrl", ""),
                    "score": r.get("score", 0),
                })

            self._log(tool, f"Found {len(matches)} PimEyes results")
            result = {"matches": matches[:30], "count": len(matches)}
            self._result(tool, result)
            return result
        except Exception as e:
            self._error(tool, f"PimEyes failed: {e}")
            return {"error": str(e), "matches": []}

    def run_facecheck(self, image_path: str) -> dict:
        """Search FaceCheck.ID API (requires paid API key)."""
        tool = "facecheck"
        api_key = os.environ.get("FACECHECK_API_KEY", "")
        if not api_key:
            self._log(tool, "FaceCheck API key not configured — skipping")
            return {"error": "no API key", "matches": []}

        self._log(tool, "Searching FaceCheck.ID...")
        try:
            import base64
            with open(image_path, "rb") as f:
                img_b64 = base64.b64encode(f.read()).decode()

            payload = json.dumps({
                "id_search": "",
                "image_base64": img_b64,
            }).encode()
            req = urllib.request.Request(
                "https://facecheck.id/api/upload",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": api_key,
                },
            )
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read())

            # Poll for results
            search_id = data.get("id_search", "")
            if search_id:
                self._log(tool, f"Search started, polling for results (ID: {search_id})...")
                for attempt in range(30):
                    if self.cancelled:
                        break
                    time.sleep(2)
                    poll_req = urllib.request.Request(
                        f"https://facecheck.id/api/search/{search_id}",
                        headers={"Authorization": api_key},
                    )
                    with urllib.request.urlopen(poll_req, timeout=15) as resp:
                        poll_data = json.loads(resp.read())
                    if poll_data.get("status") == "done":
                        data = poll_data
                        break

            matches = []
            for r in data.get("results", []):
                matches.append({
                    "url": r.get("url", ""),
                    "title": r.get("name", ""),
                    "thumbnail": r.get("base64", ""),
                    "score": r.get("score", 0),
                })

            self._log(tool, f"Found {len(matches)} FaceCheck results")
            result = {"matches": matches[:30], "count": len(matches)}
            self._result(tool, result)
            return result
        except Exception as e:
            self._error(tool, f"FaceCheck failed: {e}")
            return {"error": str(e), "matches": []}

    # Bind methods to ToolRunner
    ToolRunner.run_google_reverse_image = run_google_reverse_image
    ToolRunner.run_yandex_reverse_image = run_yandex_reverse_image
    ToolRunner.run_bing_reverse_image   = run_bing_reverse_image
    ToolRunner.run_tineye               = run_tineye
    ToolRunner.run_pimeyes              = run_pimeyes
    ToolRunner.run_facecheck            = run_facecheck


_add_face_search_methods()


# ──────────────────────────────────────────────────────────────────────────────
# New OSINT Tools — Phone, Leaked DB, IP, WHOIS
# ──────────────────────────────────────────────────────────────────────────────

def _add_new_osint_tools():

    def run_phone_lookup(self, phone: str) -> dict:
        tool = "phone_lookup"
        self._log(tool, f"Looking up: {phone}")
        results = {"phone": phone, "carrier": "", "type": "", "location": "", "valid": False}

        api_key = os.environ.get("NUMVERIFY_API_KEY", "")
        if api_key:
            try:
                url = f"http://apilayer.net/api/validate?access_key={api_key}&number={urllib.parse.quote(phone)}"
                req = urllib.request.Request(url, headers={"User-Agent": "RedBalance-OSINT/1.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read())
                results.update({"valid": data.get("valid", False), "carrier": data.get("carrier", ""),
                    "type": data.get("line_type", ""), "location": data.get("location", ""),
                    "country": data.get("country_name", "")})
                self._log(tool, f"NumVerify: valid={results['valid']}, carrier={results['carrier']}")
            except Exception as e:
                self._log(tool, f"NumVerify failed: {e}")

        abstract_key = os.environ.get("ABSTRACT_API_KEY", "")
        if abstract_key and not results["valid"]:
            try:
                url = f"https://phonevalidation.abstractapi.com/v1/?api_key={abstract_key}&phone={urllib.parse.quote(phone)}"
                with urllib.request.urlopen(urllib.request.Request(url), timeout=15) as resp:
                    data = json.loads(resp.read())
                results.update({"valid": data.get("valid", False), "carrier": data.get("carrier", ""),
                    "type": data.get("type", ""), "country": data.get("country", {}).get("name", "") if isinstance(data.get("country"), dict) else ""})
            except Exception as e:
                self._log(tool, f"Abstract API failed: {e}")

        if not api_key and not abstract_key:
            self._error(tool, "No phone API key configured (NUMVERIFY_API_KEY or ABSTRACT_API_KEY)")
        self._result(tool, results)
        return results

    def run_dehashed(self, query: str) -> dict:
        tool = "dehashed"
        api_key = os.environ.get("DEHASHED_API_KEY", "")
        if not api_key:
            self._error(tool, "DEHASHED_API_KEY not set")
            return {"error": "no API key", "entries": []}
        self._log(tool, f"Searching Dehashed for: {query}")
        try:
            search = f"email:{query}" if "@" in query else f"domain:{query}" if "." in query else f"username:{query}"
            req = urllib.request.Request(
                f"https://api.dehashed.com/search?query={urllib.parse.quote(search)}&size=100",
                headers={"Accept": "application/json", "Authorization": f"Basic {api_key}"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            entries = data.get("entries", []) or []
            self._log(tool, f"Found {len(entries)} leaked entries")
            result = {"entries": entries[:100], "total": data.get("total", 0), "query": query}
            self._result(tool, result)
            return result
        except Exception as e:
            self._error(tool, f"Dehashed failed: {e}")
            return {"error": str(e), "entries": []}

    def run_intelx(self, query: str) -> dict:
        tool = "intelx"
        api_key = os.environ.get("INTELX_API_KEY", "")
        if not api_key:
            self._error(tool, "INTELX_API_KEY not set")
            return {"error": "no API key", "results": []}
        self._log(tool, f"Searching IntelligenceX for: {query}")
        try:
            payload = json.dumps({"term": query, "maxresults": 50, "media": 0, "timeout": 10}).encode()
            req = urllib.request.Request("https://2.intelx.io/intelligent/search", data=payload,
                headers={"x-key": api_key, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                search_data = json.loads(resp.read())
            search_id = search_data.get("id", "")
            if not search_id:
                return {"error": "No search ID returned", "results": []}
            time.sleep(3)
            req2 = urllib.request.Request(f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=50",
                headers={"x-key": api_key})
            with urllib.request.urlopen(req2, timeout=20) as resp:
                result_data = json.loads(resp.read())
            records = result_data.get("records", []) or []
            self._log(tool, f"Found {len(records)} IntelX results")
            result = {"results": records[:50], "total": len(records), "query": query}
            self._result(tool, result)
            return result
        except Exception as e:
            self._error(tool, f"IntelX failed: {e}")
            return {"error": str(e), "results": []}

    def run_ip_lookup(self, ip: str) -> dict:
        tool = "ip_lookup"
        self._log(tool, f"Looking up IP: {ip}")
        try:
            token = os.environ.get("IPINFO_TOKEN", "")
            url = f"https://ipinfo.io/{urllib.parse.quote(ip)}/json"
            if token:
                url += f"?token={token}"
            req = urllib.request.Request(url, headers={"User-Agent": "RedBalance-OSINT/1.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            result = {"ip": data.get("ip", ip), "hostname": data.get("hostname", ""),
                "city": data.get("city", ""), "region": data.get("region", ""),
                "country": data.get("country", ""), "org": data.get("org", ""),
                "timezone": data.get("timezone", ""), "loc": data.get("loc", "")}
            self._log(tool, f"IP {ip}: {result['city']}, {result['country']} ({result['org']})")
            self._result(tool, result)
            return result
        except Exception as e:
            self._error(tool, f"IP lookup failed: {e}")
            return {"error": str(e)}

    def run_whois_lookup(self, domain: str) -> dict:
        tool = "whois"
        self._log(tool, f"WHOIS lookup: {domain}")
        try:
            import whois
            w = whois.whois(domain)
            result = {"domain": domain, "registrar": w.registrar or "",
                "creation_date": str(w.creation_date) if w.creation_date else "",
                "expiration_date": str(w.expiration_date) if w.expiration_date else "",
                "name_servers": list(w.name_servers) if w.name_servers else [],
                "org": w.org or "", "country": w.country or "",
                "emails": list(w.emails) if w.emails else []}
            self._log(tool, f"Registrar: {result['registrar']}")
            self._result(tool, result)
            return result
        except ImportError:
            self._error(tool, "python-whois not installed")
            return {"error": "python-whois not installed"}
        except Exception as e:
            self._error(tool, f"WHOIS failed: {e}")
            return {"error": str(e)}

    ToolRunner.run_phone_lookup  = run_phone_lookup
    ToolRunner.run_dehashed      = run_dehashed
    ToolRunner.run_intelx        = run_intelx
    ToolRunner.run_ip_lookup     = run_ip_lookup
    ToolRunner.run_whois_lookup  = run_whois_lookup


_add_new_osint_tools()
