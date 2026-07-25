# Recon — Subdomain & Security Scanner

A dark, ops-console-styled Streamlit dashboard for authorized subdomain
enumeration and security reconnaissance.

## Run locally

```bash
pip install -r requirements.txt
streamlit run scanner.py
```

## Deploy on Streamlit Community Cloud

1. Push `scanner.py`, `engine.py`, `theme.py`, and `requirements.txt` to your GitHub repo (same folder).
2. On share.streamlit.io, point the app at `scanner.py`.
3. No secrets/config needed — everything runs with public network calls (DNS, HTTP, crt.sh).

## What's new vs. the original single-file version

**Performance**
- Per-host pipeline now runs HTTP probing and port scanning *concurrently* instead of
  sequentially (`ThreadPoolExecutor` fan-out per host), on top of the existing
  cross-host thread pool — noticeably faster on hosts where ports are scanned.
- crt.sh hits are resolved concurrently instead of one DNS lookup at a time.
- Response timing is captured per host so slow endpoints are visible, not just implied.

**New functionality**
- **Risk scoring (0–100) + level** per host, combining missing headers, plain-HTTP,
  risky open ports (DB/RDP/Telnet/etc.), near-expiry or invalid TLS certs, and exposed
  admin panels.
- **Security header letter grades (A–F)**, not just an N/M count.
- **Lightweight technology fingerprinting** (WordPress, Nginx, Apache, PHP, IIS, jQuery,
  Drupal, Laravel, Express, cPanel, phpMyAdmin) from response headers and page markup,
  each with a short advisory note — a starting point for manual review, not a CVE feed.
- **Scan history** (session-scoped, last 8 scans) with a **side-by-side comparison** tab:
  new subdomains, disappeared subdomains, and risk-level changes between any two scans.
- **CSV export** alongside the existing JSON/text reports.
- **Domain validation** with clear inline errors instead of best-effort string stripping.
- Sortable/filterable detailed view (live-only toggle, sort by risk/alphabetical/response time).

**Design**
- Full dark "ops console" visual theme (JetBrains Mono + Inter, teal accent, animated
  radar-sweep mark) instead of default Streamlit styling.
- Grade badges and risk pills for instant visual triage instead of scanning table columns.
- Restructured into `engine.py` (pure scanning logic, reusable/testable) + `theme.py`
  (CSS) + `scanner.py` (UI), instead of one 845-line file.

## Responsible use

Only scan domains you own or have explicit written permission to test. Unauthorized
subdomain enumeration and port scanning may be illegal in your jurisdiction.
