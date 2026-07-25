"""
Recon Engine
============
All non-UI logic for the subdomain / security recon tool: DNS enumeration,
HTTP probing, header analysis, port scanning, SSL inspection, lightweight
technology fingerprinting, risk scoring, and result persistence.

Kept dependency-free beyond requests / dnspython / stdlib so the app stays
a single `pip install -r requirements.txt` away from running anywhere.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable

import requests
import dns.resolver

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "ns3",
    "autodiscover", "api", "dev", "staging", "test", "vpn", "portal",
    "admin", "app", "blog", "shop", "store", "cdn", "static", "assets",
    "m", "mobile", "secure", "login", "cpanel", "whm", "webdisk",
    "docs", "support", "help", "status", "dashboard", "cloud", "git",
    "gitlab", "jenkins", "jira", "confluence", "wiki", "internal",
    "intranet", "remote", "gateway", "proxy", "db", "database", "sql",
    "mysql", "redis", "cache", "media", "images", "img", "video",
    "stream", "beta", "demo", "sandbox", "uat", "qa", "prod",
    "production", "old", "new", "backup", "mx", "mx1", "mx2", "ns",
    "dns", "web", "web1", "web2", "server", "host", "cp", "chat",
    "forum", "community", "news", "events", "careers", "jobs", "hr",
]

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

RISKY_PORTS = {23, 445, 3306, 3389, 5432, 6379, 9200, 27017}

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS, preventing downgrade/SSL-strip attacks.",
    "Content-Security-Policy": "Mitigates XSS and data-injection by restricting resource origins.",
    "X-Content-Type-Options": "Prevents MIME-sniffing (should be 'nosniff').",
    "X-Frame-Options": "Prevents clickjacking via iframe embedding.",
    "Referrer-Policy": "Controls how much referrer info is leaked to other sites.",
    "Permissions-Policy": "Restricts which browser features/APIs the page can use.",
    "X-XSS-Protection": "Legacy browser XSS filter toggle (deprecated but sometimes still checked).",
}

# --------------------------------------------------------------------------
# Lightweight technology fingerprinting (header + body signatures)
# --------------------------------------------------------------------------
# Not a CVE feed — a curated set of "if you see this, go check advisories"
# nudges. Deliberately conservative: only flags well-known, long-lived
# version-disclosure patterns, never claims a specific CVE applies.

TECH_SIGNATURES = [
    # (label, header_regexes, body_regexes, advisory)
    ("WordPress", [], [r'wp-content/', r'wp-includes/'],
     "Check installed plugin versions — most WP CVEs are plugin-side."),
    ("Nginx", [(r'^Server$', r'nginx/([\d.]+)')], [],
     "Version disclosed in Server header — consider suppressing it."),
    ("Apache", [(r'^Server$', r'Apache/([\d.]+)')], [],
     "Version disclosed in Server header — consider suppressing it."),
    ("PHP", [(r'^X-Powered-By$', r'PHP/([\d.]+)')], [],
     "PHP version disclosed — verify it's still receiving security patches."),
    ("IIS", [(r'^Server$', r'Microsoft-IIS/([\d.]+)')], [],
     "Legacy IIS versions have known CVEs — verify patch level."),
    ("jQuery", [], [r'jquery[-.]([\d.]+)(?:\.min)?\.js'],
     "Older jQuery (<3.5) has known XSS issues — verify version."),
    ("Drupal", [], [r'sites/(?:default|all)/', r'Drupal\.settings'],
     "Check core + module versions against Drupal security advisories."),
    ("Laravel", [(r'^Set-Cookie$', r'laravel_session')], [],
     "Framework identified via cookie — ensure debug mode is off in prod."),
    ("Express", [(r'^X-Powered-By$', r'Express')], [],
     "Framework disclosed — consider removing X-Powered-By in production."),
    ("cPanel", [], [r'cpanel', r'whm'],
     "Admin panel exposed — restrict access by IP if possible."),
    ("phpMyAdmin", [], [r'phpMyAdmin'],
     "Database admin UI exposed — should never be internet-facing without IP allowlisting."),
]

REQUEST_TIMEOUT = 5
DNS_TIMEOUT = 3
PORT_SCAN_TIMEOUT = 1.0
MAX_WORKERS_DNS = 30
MAX_WORKERS_HOST = 12  # hosts processed concurrently in the post-DNS pipeline
MAX_WORKERS_PORTS = 16  # ports-per-host, run as a nested pool


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

@dataclass
class SubdomainResult:
    subdomain: str
    resolved_ips: list = field(default_factory=list)
    is_live: bool = False
    scheme: Optional[str] = None
    status_code: Optional[int] = None
    server_header: Optional[str] = None
    headers: dict = field(default_factory=dict)
    header_analysis: dict = field(default_factory=dict)
    header_score: str = "N/A"
    header_grade: str = "N/A"
    open_ports: dict = field(default_factory=dict)
    ssl_info: dict = field(default_factory=dict)
    technologies: list = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "unknown"
    risk_reasons: list = field(default_factory=list)
    response_ms: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self):
        return asdict(self)


# --------------------------------------------------------------------------
# Step 1: Subdomain enumeration
# --------------------------------------------------------------------------

def resolve_subdomain(name: str, dns_server: Optional[str] = None) -> Optional[list]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    if dns_server:
        resolver.nameservers = [dns_server]
    try:
        answers = resolver.resolve(name, "A")
        return [a.to_text() for a in answers]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return None
    except Exception:
        return None


def diagnose_dns_health(domain: str, dns_server: Optional[str] = None) -> Optional[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    if dns_server:
        resolver.nameservers = [dns_server]

    try:
        resolver.resolve("www.google.com", "A")
    except dns.exception.Timeout:
        if dns_server:
            return (
                f"DNS lookups to {dns_server} are timing out. That server may be "
                "unreachable from this network. Try a different DNS server or "
                "switch back to system default."
            )
        return (
            "DNS lookups are timing out on this machine's default resolver. "
            "Try switching to a public DNS server (e.g. 8.8.8.8) in the sidebar."
        )
    except Exception as e:
        return f"DNS resolver appears misconfigured or blocked ({type(e).__name__})."

    try:
        resolver.resolve(domain, "A")
    except dns.resolver.NXDOMAIN:
        return f"`{domain}` does not appear to exist (NXDOMAIN). Double-check the spelling."
    except dns.resolver.NoAnswer:
        return None
    except dns.exception.Timeout:
        return f"Lookup for `{domain}` itself timed out. Your network/DNS may be rate-limiting queries."
    except Exception:
        return None

    return None


def enumerate_via_wordlist(domain: str, wordlist: list, progress_cb=None,
                            dns_server: Optional[str] = None) -> dict:
    candidates = [f"{word}.{domain}" for word in wordlist]
    found = {}
    total = len(candidates)
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_DNS) as executor:
        future_map = {
            executor.submit(resolve_subdomain, c, dns_server): c for c in candidates
        }
        for future in concurrent.futures.as_completed(future_map):
            candidate = future_map[future]
            done += 1
            if progress_cb:
                progress_cb(done, total, candidate)
            ips = future.result()
            if ips:
                found[candidate] = ips
    return found


def enumerate_via_crtsh(domain: str) -> set:
    names = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=10,
            headers={"User-Agent": "recon-tool/2.0"},
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                value = entry.get("name_value", "")
                for line in value.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(domain) and "*" not in line:
                        names.add(line)
    except Exception:
        pass
    return names


# --------------------------------------------------------------------------
# Step 2: HTTP liveness probing
# --------------------------------------------------------------------------

def probe_http(subdomain: str) -> Optional[dict]:
    session = requests.Session()
    session.headers.update({"User-Agent": "recon-tool/2.0"})
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        start = time.monotonic()
        try:
            resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=True)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return {
                "scheme": scheme,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "final_url": resp.url,
                "body_sample": resp.text[:20000] if resp.text else "",
                "response_ms": elapsed_ms,
            }
        except requests.exceptions.SSLError:
            if scheme == "https":
                try:
                    resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=False)
                    elapsed_ms = int((time.monotonic() - start) * 1000)
                    return {
                        "scheme": scheme,
                        "status_code": resp.status_code,
                        "headers": dict(resp.headers),
                        "final_url": resp.url,
                        "body_sample": resp.text[:20000] if resp.text else "",
                        "response_ms": elapsed_ms,
                        "ssl_verify_failed": True,
                    }
                except Exception:
                    continue
            continue
        except requests.exceptions.RequestException:
            continue
    return None


# --------------------------------------------------------------------------
# Step 3: Security header analysis
# --------------------------------------------------------------------------

def analyze_headers(headers: dict) -> tuple:
    normalized = {k.lower(): v for k, v in headers.items()}
    analysis = {}
    present_count = 0

    for header, rationale in SECURITY_HEADERS.items():
        key = header.lower()
        if key in normalized:
            present_count += 1
            analysis[header] = {"present": True, "value": normalized[key], "note": rationale}
        else:
            analysis[header] = {"present": False, "value": None, "note": f"MISSING — {rationale}"}

    set_cookie = normalized.get("set-cookie", "")
    if set_cookie:
        cookie_issues = []
        if "secure" not in set_cookie.lower():
            cookie_issues.append("missing 'Secure' flag")
        if "httponly" not in set_cookie.lower():
            cookie_issues.append("missing 'HttpOnly' flag")
        if cookie_issues:
            analysis["Set-Cookie"] = {
                "present": True, "value": set_cookie,
                "note": f"Cookie issues: {', '.join(cookie_issues)}",
            }

    score = f"{present_count}/{len(SECURITY_HEADERS)}"
    grade = score_to_grade(present_count, len(SECURITY_HEADERS))
    return analysis, score, grade


def score_to_grade(present: int, total: int) -> str:
    pct = present / total if total else 0
    if pct >= 0.85:
        return "A"
    if pct >= 0.7:
        return "B"
    if pct >= 0.5:
        return "C"
    if pct >= 0.3:
        return "D"
    return "F"


# --------------------------------------------------------------------------
# Step 4: Technology fingerprinting
# --------------------------------------------------------------------------

def fingerprint_technologies(headers: dict, body_sample: str) -> list:
    found = []
    header_items = list(headers.items())
    for label, header_rules, body_rules, advisory in TECH_SIGNATURES:
        hit = False
        version = None
        for header_name_re, value_re in header_rules:
            for hk, hv in header_items:
                if re.match(header_name_re, hk, re.IGNORECASE):
                    m = re.search(value_re, hv, re.IGNORECASE)
                    if m:
                        hit = True
                        version = m.group(1) if m.groups() else None
        if not hit and body_sample:
            for pattern in body_rules:
                m = re.search(pattern, body_sample, re.IGNORECASE)
                if m:
                    hit = True
                    if m.groups():
                        version = m.group(1)
        if hit:
            found.append({"name": label, "version": version, "advisory": advisory})
    return found


# --------------------------------------------------------------------------
# Step 5: Port scanning
# --------------------------------------------------------------------------

def scan_port(host: str, port: int, timeout=PORT_SCAN_TIMEOUT) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except (socket.timeout, socket.error, OSError):
        return False


def scan_common_ports(host: str) -> dict:
    open_ports = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_PORTS) as executor:
        future_map = {
            executor.submit(scan_port, host, port): (port, service)
            for port, service in COMMON_PORTS.items()
        }
        for future in concurrent.futures.as_completed(future_map):
            port, service = future_map[future]
            try:
                if future.result():
                    open_ports[port] = service
            except Exception:
                pass
    return open_ports


# --------------------------------------------------------------------------
# Step 6: SSL certificate details
# --------------------------------------------------------------------------

def get_ssl_certificate_info(hostname: str, port: int = 443) -> dict:
    info = {}
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

                info["subject"] = dict(x[0] for x in cert.get("subject", []))
                info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                info["version"] = cert.get("version")
                info["serial_number"] = cert.get("serialNumber")
                info["not_before"] = cert.get("notBefore")
                info["not_after"] = cert.get("notAfter")
                info["subject_alt_names"] = [x[1] for x in cert.get("subjectAltName", [])]
                info["cipher_suite"] = cipher[0] if cipher else None
                info["tls_version"] = cipher[1] if cipher else None

                try:
                    expire_date = datetime.datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    ).replace(tzinfo=datetime.timezone.utc)
                    days_left = (expire_date - datetime.datetime.now(datetime.timezone.utc)).days
                    info["days_until_expiry"] = days_left
                    info["expiry_warning"] = days_left < 30
                except Exception:
                    info["days_until_expiry"] = None

                info["verified"] = True
    except ssl.SSLCertVerificationError as e:
        info["verified"] = False
        info["error"] = f"Certificate verification failed: {e}"
    except (socket.timeout, socket.error, ConnectionRefusedError, OSError) as e:
        info["error"] = f"Connection failed: {e}"
    except Exception as e:
        info["error"] = str(e)
    return info


# --------------------------------------------------------------------------
# Step 7: Risk scoring
# --------------------------------------------------------------------------

def compute_risk(result: SubdomainResult) -> tuple:
    """Return (score 0-100, level, reasons). Higher = riskier."""
    score = 0
    reasons = []

    if result.is_live:
        if result.header_score != "N/A":
            present = int(result.header_score.split("/")[0])
            total = int(result.header_score.split("/")[1])
            missing = total - present
            score += missing * 8
            if missing >= 4:
                reasons.append(f"{missing} of {total} security headers missing")
        if result.scheme == "http":
            score += 15
            reasons.append("Serving over plain HTTP, not HTTPS")

    risky_open = [p for p in result.open_ports if p in RISKY_PORTS]
    if risky_open:
        score += 15 * len(risky_open)
        names = ", ".join(f"{p}/{COMMON_PORTS.get(p, '?')}" for p in sorted(risky_open))
        reasons.append(f"Sensitive port(s) exposed: {names}")

    if result.ssl_info:
        if result.ssl_info.get("expiry_warning"):
            score += 20
            reasons.append("SSL certificate expires within 30 days")
        if result.ssl_info.get("verified") is False:
            score += 15
            reasons.append("SSL certificate failed verification")

    for tech in result.technologies:
        if tech.get("name") in ("phpMyAdmin", "cPanel"):
            score += 20
            reasons.append(f"{tech['name']} admin interface publicly reachable")

    score = min(score, 100)
    if score == 0:
        level = "clean"
    elif score < 25:
        level = "low"
    elif score < 50:
        level = "medium"
    elif score < 75:
        level = "high"
    else:
        level = "critical"
    return score, level, reasons


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def process_subdomain(subdomain: str, ips: list, do_ports: bool, do_ssl: bool) -> SubdomainResult:
    result = SubdomainResult(subdomain=subdomain, resolved_ips=ips or [])

    # Kick off HTTP probe and port scan concurrently — they're independent.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        http_future = pool.submit(probe_http, subdomain)
        ports_future = pool.submit(scan_common_ports, ips[0] if ips else subdomain) if do_ports else None

        http_info = http_future.result()
        if ports_future is not None:
            result.open_ports = ports_future.result()

    if http_info:
        result.is_live = True
        result.scheme = http_info["scheme"]
        result.status_code = http_info["status_code"]
        result.headers = http_info["headers"]
        result.server_header = http_info["headers"].get("Server", "Unknown")
        result.response_ms = http_info.get("response_ms")

        analysis, score, grade = analyze_headers(http_info["headers"])
        result.header_analysis = analysis
        result.header_score = score
        result.header_grade = grade
        result.technologies = fingerprint_technologies(http_info["headers"], http_info.get("body_sample", ""))

        if http_info.get("ssl_verify_failed"):
            result.error = "HTTPS reachable but certificate verification failed."

    if do_ssl and result.is_live and result.scheme == "https":
        result.ssl_info = get_ssl_certificate_info(subdomain)
    elif do_ssl and 443 in result.open_ports:
        result.ssl_info = get_ssl_certificate_info(subdomain)

    result.risk_score, result.risk_level, result.risk_reasons = compute_risk(result)
    return result


def run_full_scan(domain: str, wordlist: list, use_crtsh: bool,
                   do_ports: bool, do_ssl: bool, progress_cb=None, status_cb=None,
                   dns_server: Optional[str] = None):
    dns_issue = diagnose_dns_health(domain, dns_server=dns_server)
    if dns_issue and status_cb:
        status_cb(f"DNS check: {dns_issue}")

    if status_cb:
        status_cb("Enumerating subdomains via DNS brute-force...")
    found = enumerate_via_wordlist(domain, wordlist, progress_cb=progress_cb, dns_server=dns_server)

    if use_crtsh:
        if status_cb:
            status_cb("Querying certificate transparency logs (crt.sh)...")
        crt_names = enumerate_via_crtsh(domain)
        # Resolve crt.sh hits concurrently instead of one-by-one.
        to_check = [n for n in crt_names if n not in found]
        if to_check:
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_DNS) as executor:
                future_map = {executor.submit(resolve_subdomain, n, dns_server): n for n in to_check}
                for future in concurrent.futures.as_completed(future_map):
                    n = future_map[future]
                    ips = future.result()
                    if ips:
                        found[n] = ips

    if domain not in found:
        ips = resolve_subdomain(domain, dns_server=dns_server)
        if ips:
            found[domain] = ips

    if status_cb:
        status_cb(f"Found {len(found)} resolvable subdomain(s). Probing HTTP/HTTPS, ports & TLS...")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_HOST) as executor:
        future_map = {
            executor.submit(process_subdomain, sub, ips, do_ports, do_ssl): sub
            for sub, ips in found.items()
        }
        completed = 0
        for future in concurrent.futures.as_completed(future_map):
            completed += 1
            sub = future_map[future]
            if status_cb:
                status_cb(f"Analyzed {completed}/{len(found)}: {sub}")
            try:
                results.append(future.result())
            except Exception as e:
                results.append(SubdomainResult(subdomain=sub, resolved_ips=found[sub], error=str(e)))

    results.sort(key=lambda r: (not r.is_live, -r.risk_score, r.subdomain))
    return results, dns_issue


# --------------------------------------------------------------------------
# Persistence: reports + scan history
# --------------------------------------------------------------------------

def save_results_json(domain: str, results: list, filepath: str):
    payload = {
        "domain": domain,
        "scan_time_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_subdomains_found": len(results),
        "live_count": sum(1 for r in results if r.is_live),
        "results": [r.to_dict() for r in results],
    }
    with open(filepath, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    return payload


def save_results_text(domain: str, results: list, filepath: str):
    lines = []
    lines.append(f"Recon Report for {domain}")
    lines.append(f"Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}")
    lines.append(f"Total subdomains found: {len(results)}")
    lines.append(f"Live (HTTP/HTTPS responsive): {sum(1 for r in results if r.is_live)}")
    lines.append("=" * 70)

    for r in results:
        lines.append(f"\nSubdomain: {r.subdomain}")
        lines.append(f"  Resolved IPs: {', '.join(r.resolved_ips) if r.resolved_ips else 'N/A'}")
        lines.append(f"  Live: {r.is_live}")
        lines.append(f"  Risk: {r.risk_level} ({r.risk_score}/100)")
        if r.is_live:
            lines.append(f"  Scheme/Status: {r.scheme} / {r.status_code}")
            lines.append(f"  Server header: {r.server_header}")
            lines.append(f"  Security header score: {r.header_score} (grade {r.header_grade})")
            missing = [h for h, v in r.header_analysis.items() if not v.get("present")]
            if missing:
                lines.append(f"  Missing headers: {', '.join(missing)}")
        if r.technologies:
            techs = ", ".join(t["name"] + (f" {t['version']}" if t.get("version") else "") for t in r.technologies)
            lines.append(f"  Technologies: {techs}")
        if r.open_ports:
            port_str = ", ".join(f"{p}/{s}" for p, s in sorted(r.open_ports.items()))
            lines.append(f"  Open ports: {port_str}")
        if r.ssl_info:
            if r.ssl_info.get("verified"):
                lines.append(f"  SSL issuer: {r.ssl_info.get('issuer', {}).get('organizationName', 'Unknown')}")
                lines.append(f"  SSL expires: {r.ssl_info.get('not_after')} ({r.ssl_info.get('days_until_expiry')} days left)")
            elif r.ssl_info.get("error"):
                lines.append(f"  SSL error: {r.ssl_info.get('error')}")
        if r.risk_reasons:
            lines.append(f"  Risk factors: {'; '.join(r.risk_reasons)}")
        if r.error:
            lines.append(f"  Note: {r.error}")

    with open(filepath, "w") as f:
        f.write("\n".join(lines))


def results_to_csv_rows(results: list) -> list:
    rows = [[
        "Subdomain", "Live", "IPs", "Scheme", "Status", "Server", "Technologies",
        "Header Score", "Header Grade", "Open Ports", "SSL Expires (days)",
        "Risk Level", "Risk Score", "Response (ms)",
    ]]
    for r in results:
        rows.append([
            r.subdomain,
            "yes" if r.is_live else "no",
            ";".join(r.resolved_ips),
            r.scheme or "",
            r.status_code or "",
            r.server_header or "",
            ";".join(t["name"] for t in r.technologies),
            r.header_score,
            r.header_grade,
            ";".join(str(p) for p in sorted(r.open_ports)),
            r.ssl_info.get("days_until_expiry", "") if r.ssl_info else "",
            r.risk_level,
            r.risk_score,
            r.response_ms or "",
        ])
    return rows


def validate_domain(raw: str) -> tuple:
    """Clean + sanity check a domain string. Returns (clean_domain, error|None)."""
    domain = raw.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].strip()
    if not domain:
        return "", "Please enter a target domain."
    if not re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", domain):
        return domain, f"`{domain}` doesn't look like a valid domain (e.g. example.com)."
    return domain, None


def validate_ip(raw: str) -> bool:
    try:
        ipaddress.ip_address(raw)
        return True
    except ValueError:
        return False
