"""
Recon — Subdomain Enumeration & Security Reconnaissance Dashboard
===================================================================
Performs:
  1. Subdomain enumeration (DNS brute-force + certificate-transparency via crt.sh)
  2. Concurrent HTTP/HTTPS liveness probing
  3. Security header analysis with letter grading
  4. Common open-port scanning (TCP connect scan)
  5. SSL/TLS certificate inspection
  6. Lightweight technology fingerprinting with advisory notes
  7. Per-host risk scoring
  8. Scan history with side-by-side comparison
  9. JSON / text / CSV export

Run with:  streamlit run scanner.py

RESPONSIBLE USE
----------------
Only run this against domains you own or have explicit written permission
to test. Subdomain enumeration and port scanning against third-party
infrastructure without authorization may be illegal in your jurisdiction.
"""

import csv
import io
import os
import tempfile
import time
import ipaddress
import datetime

import streamlit as st

from engine import (
    DEFAULT_WORDLIST, SECURITY_HEADERS, COMMON_PORTS,
    run_full_scan, save_results_json, save_results_text, results_to_csv_rows,
    validate_domain, validate_ip,
)
from theme import build_css, grade_badge, risk_pill, tech_chips

st.set_page_config(page_title="Recon — Subdomain & Security Scanner", page_icon="🛰️", layout="wide")

MAX_HISTORY = 8

if "theme_mode" not in st.session_state:
    st.session_state["theme_mode"] = "light"

st.markdown(build_css(st.session_state["theme_mode"]), unsafe_allow_html=True)


# --------------------------------------------------------------------------
# Session state setup
# --------------------------------------------------------------------------

def init_state():
    defaults = {
        "results": None,
        "domain_scanned": None,
        "json_path": None,
        "text_path": None,
        "save_format": "Both",
        "history": [],  # list of {"domain", "timestamp", "results", "duration"}
        "compare_a": None,
        "compare_b": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


init_state()


# --------------------------------------------------------------------------
# Hero
# --------------------------------------------------------------------------

st.markdown(
    """
    <div class="recon-hero">
        <div class="recon-sweep"></div>
        <div>
            <h1>RECON // Subdomain &amp; Security Scanner</h1>
            <p>DNS enumeration · HTTP probing · header grading · port scan · TLS inspection · tech fingerprinting</p>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="mobile-sidebar-hint">
        <div class="arrow-icon">›</div>
        <div>Tap the <strong>arrow in the top-left corner</strong> to open scan settings
        (domain, wordlist, checks) and start a scan.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.warning(
    "**Authorized use only.** Only scan domains you own or have explicit written permission to test. "
    "Unauthorized scanning may be illegal in your jurisdiction.",
    icon="⚠️",
)

# --------------------------------------------------------------------------
# Sidebar — configuration
# --------------------------------------------------------------------------

with st.sidebar:
    theme_choice = st.radio(
        "Appearance", ["Dark", "Light"],
        index=0 if st.session_state["theme_mode"] == "dark" else 1,
        horizontal=True, key="theme_radio",
    )
    new_mode = theme_choice.lower()
    if new_mode != st.session_state["theme_mode"]:
        st.session_state["theme_mode"] = new_mode
        st.rerun()

    st.divider()
    st.header("Scan configuration")
    domain = st.text_input("Target domain", placeholder="example.com")

    with st.expander("Enumeration", expanded=True):
        use_default_wordlist = st.checkbox("Use built-in wordlist", value=True,
                                            help=f"{len(DEFAULT_WORDLIST)} common prefixes")
        custom_words = st.text_area("Additional prefixes (comma-separated)", placeholder="foo, bar, baz")
        use_crtsh = st.checkbox("Also query crt.sh (certificate transparency)", value=True)

    with st.expander("DNS resolver"):
        DNS_PRESETS = {
            "System default": None,
            "Google (8.8.8.8)": "8.8.8.8",
            "Cloudflare (1.1.1.1)": "1.1.1.1",
            "Quad9 (9.9.9.9)": "9.9.9.9",
            "Custom...": "custom",
        }
        dns_choice = st.selectbox(
            "DNS server", list(DNS_PRESETS.keys()), index=0,
            help="Use this if your default DNS is slow, blocked, or unreliable.",
        )
        dns_server = DNS_PRESETS[dns_choice]
        if dns_server == "custom":
            dns_server = st.text_input("Custom DNS server IP", placeholder="e.g. 4.2.2.2").strip() or None

    with st.expander("Additional checks", expanded=True):
        do_ports = st.checkbox("Scan common ports", value=True)
        do_ssl = st.checkbox("Fetch SSL certificate details", value=True)

    with st.expander("Output"):
        save_format = st.radio("Report format", ["JSON", "Text", "Both"], index=2, horizontal=True)

    run_button = st.button("🚀 Start scan", type="primary", use_container_width=True)

    if st.session_state.history:
        st.divider()
        st.caption(f"Scan history ({len(st.session_state.history)}/{MAX_HISTORY})")
        for i, h in enumerate(reversed(st.session_state.history)):
            st.caption(f"`{h['domain']}` · {h['timestamp']} · {len(h['results'])} found")


# --------------------------------------------------------------------------
# Run scan
# --------------------------------------------------------------------------

if run_button:
    domain_clean, err = validate_domain(domain)
    if err:
        st.error(err)
        st.stop()

    if dns_choice == "Custom..." and not dns_server:
        st.error("Please enter a custom DNS server IP, or pick a different resolver option.")
        st.stop()
    if dns_server and not validate_ip(dns_server):
        st.error(f"`{dns_server}` doesn't look like a valid IP address.")
        st.stop()

    wordlist = list(DEFAULT_WORDLIST) if use_default_wordlist else []
    if custom_words.strip():
        extra = [w.strip() for w in custom_words.split(",") if w.strip()]
        wordlist.extend(extra)
    wordlist = sorted(set(wordlist))

    if not wordlist:
        st.error("Wordlist is empty — enable the built-in list or add custom prefixes.")
        st.stop()

    progress_bar = st.progress(0.0, text="Starting DNS enumeration...")
    status_placeholder = st.empty()

    def progress_cb(done, total, candidate):
        progress_bar.progress(done / total, text=f"DNS check {done}/{total}: {candidate}")

    def status_cb(msg):
        status_placeholder.info(msg)

    start_time = time.monotonic()
    try:
        with st.spinner("Running scan..."):
            results, dns_issue = run_full_scan(
                domain_clean, wordlist, use_crtsh, do_ports, do_ssl,
                progress_cb=progress_cb, status_cb=status_cb, dns_server=dns_server,
            )
    except Exception as e:
        progress_bar.empty()
        status_placeholder.empty()
        st.error(f"Scan failed with an unexpected error: {e}")
        st.session_state.results = None
        st.session_state.domain_scanned = None
        st.stop()

    duration = time.monotonic() - start_time
    progress_bar.progress(1.0, text=f"Scan complete in {duration:.1f}s.")

    if not results:
        if dns_issue:
            status_placeholder.warning(
                f"Scan finished but found 0 resolvable subdomains for `{domain_clean}`. Likely cause: {dns_issue}"
            )
        else:
            status_placeholder.warning(
                f"Scan finished but found 0 resolvable subdomains for `{domain_clean}`. "
                "DNS itself looks healthy, so none of the wordlist prefixes exist for this domain. "
                "Try adding custom prefixes or enabling crt.sh."
            )
    else:
        status_placeholder.success(f"Done in {duration:.1f}s — {len(results)} subdomain(s) found.")

    st.session_state.results = results
    st.session_state.domain_scanned = domain_clean

    # Push to history (cap length, dedupe same-domain by replacing latest)
    st.session_state.history.append({
        "domain": domain_clean,
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "results": results,
        "duration": duration,
    })
    st.session_state.history = st.session_state.history[-MAX_HISTORY:]

    json_path = os.path.join(tempfile.gettempdir(), f"{domain_clean}_recon.json")
    text_path = os.path.join(tempfile.gettempdir(), f"{domain_clean}_recon.txt")
    st.session_state.json_path = None
    st.session_state.text_path = None
    try:
        if save_format in ("JSON", "Both"):
            save_results_json(domain_clean, results, json_path)
            st.session_state.json_path = json_path
        if save_format in ("Text", "Both"):
            save_results_text(domain_clean, results, text_path)
            st.session_state.text_path = text_path
    except OSError as e:
        st.error(f"Could not write report file(s): {e}")
    st.session_state.save_format = save_format


# --------------------------------------------------------------------------
# Display results
# --------------------------------------------------------------------------

results = st.session_state.results
domain_scanned = st.session_state.get("domain_scanned")

if results is not None and domain_scanned is not None:
    live_results = [r for r in results if r.is_live]

    st.header(f"Results for `{domain_scanned}`")

    if not results:
        st.info(
            "No subdomains were found. See the warning above for likely causes. "
            "You can still download an empty report below, or try a new scan with different settings."
        )

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Subdomains found", len(results))
    col2.metric("Live (HTTP/HTTPS)", len(live_results))
    col3.metric("With open ports", sum(1 for r in results if r.open_ports))
    critical_count = sum(1 for r in results if r.risk_level in ("high", "critical"))
    col4.metric("High/critical risk", critical_count)
    avg_score = "N/A"
    if live_results:
        scores = [int(r.header_score.split("/")[0]) for r in live_results if r.header_score != "N/A"]
        if scores:
            avg_score = f"{sum(scores)/len(scores):.1f}/{len(SECURITY_HEADERS)}"
    col5.metric("Avg. header score", avg_score)

    # ---- Downloads ----
    json_path = st.session_state.get("json_path")
    text_path = st.session_state.get("text_path")
    dl_col1, dl_col2, dl_col3 = st.columns(3)
    if json_path and os.path.isfile(json_path):
        with open(json_path, "rb") as f:
            dl_col1.download_button("⬇️ JSON report", f, file_name=f"{domain_scanned}_recon.json",
                                     mime="application/json", use_container_width=True)
    elif st.session_state.get("save_format") in ("JSON", "Both"):
        dl_col1.caption("JSON report unavailable.")

    if text_path and os.path.isfile(text_path):
        with open(text_path, "rb") as f:
            dl_col2.download_button("⬇️ Text report", f, file_name=f"{domain_scanned}_recon.txt",
                                     mime="text/plain", use_container_width=True)
    elif st.session_state.get("save_format") in ("Text", "Both"):
        dl_col2.caption("Text report unavailable.")

    # CSV export — built in-memory, no disk round trip needed
    csv_buffer = io.StringIO()
    csv.writer(csv_buffer).writerows(results_to_csv_rows(results))
    dl_col3.download_button("⬇️ CSV (spreadsheet)", csv_buffer.getvalue(),
                             file_name=f"{domain_scanned}_recon.csv", mime="text/csv",
                             use_container_width=True)

    st.divider()

    tab1, tab2, tab3, tab4 = st.tabs(["📋 Overview", "🔎 Detailed view", "🧬 Technologies", "📊 Compare scans"])

    # ---- Tab 1: Overview table ----
    with tab1:
        table_rows = []
        for r in results:
            table_rows.append({
                "Subdomain": r.subdomain,
                "Live": "✅" if r.is_live else "❌",
                "Risk": r.risk_level,
                "IPs": ", ".join(r.resolved_ips) if r.resolved_ips else "-",
                "Status": r.status_code or "-",
                "Server": r.server_header or "-",
                "Header grade": r.header_grade,
                "Open ports": ", ".join(str(p) for p in sorted(r.open_ports)) if r.open_ports else "-",
                "SSL exp. (days)": r.ssl_info.get("days_until_expiry", "-") if r.ssl_info else "-",
                "Resp. (ms)": r.response_ms or "-",
            })
        st.dataframe(
            table_rows, use_container_width=True, hide_index=True,
            column_config={
                "Risk": st.column_config.TextColumn(help="clean < low < medium < high < critical"),
            },
        )

    # ---- Tab 2: Detailed view ----
    with tab2:
        filter_col1, filter_col2 = st.columns([2, 1])
        show_only_live = filter_col1.checkbox("Show only live hosts", value=False)
        sort_choice = filter_col2.selectbox("Sort by", ["Risk (default)", "Alphabetical", "Response time"])

        display_results = [r for r in results if (r.is_live or not show_only_live)]
        if sort_choice == "Alphabetical":
            display_results = sorted(display_results, key=lambda r: r.subdomain)
        elif sort_choice == "Response time":
            display_results = sorted(display_results, key=lambda r: (r.response_ms is None, r.response_ms or 0))

        for r in display_results:
            icon = "🟢" if r.is_live else "⚪"
            header_label = f"{icon} {r.subdomain}"
            with st.expander(header_label):
                top1, top2, top3 = st.columns([1, 1, 3])
                with top1:
                    st.markdown(f"**Header grade**<br>{grade_badge(r.header_grade)}", unsafe_allow_html=True)
                with top2:
                    st.markdown(f"**Risk**<br>{risk_pill(r.risk_level, r.risk_score)}", unsafe_allow_html=True)
                with top3:
                    if r.risk_reasons:
                        st.markdown("**Why:** " + "; ".join(r.risk_reasons))

                st.write(f"**Resolved IPs:** {', '.join(r.resolved_ips) if r.resolved_ips else 'N/A'}")

                if r.is_live:
                    meta = f"**Scheme:** {r.scheme} | **Status:** {r.status_code}"
                    if r.response_ms is not None:
                        meta += f" | **Response:** {r.response_ms} ms"
                    st.write(meta)
                    st.write(f"**Server header:** {r.server_header}")

                    st.markdown(f"**Security headers ({r.header_score}):**")
                    header_table = []
                    for h, details in r.header_analysis.items():
                        header_table.append({
                            "Header": h,
                            "Present": "✅" if details["present"] else "❌",
                            "Value / Note": details["value"] if details["present"] else details["note"],
                        })
                    st.dataframe(header_table, use_container_width=True, hide_index=True)

                    if r.technologies:
                        st.markdown("**Technologies detected:**")
                        st.markdown(tech_chips(r.technologies), unsafe_allow_html=True)
                else:
                    st.write("No HTTP/HTTPS response received.")

                if r.open_ports:
                    st.markdown("**Open ports:**")
                    port_table = [{"Port": p, "Service": s} for p, s in sorted(r.open_ports.items())]
                    st.dataframe(port_table, use_container_width=True, hide_index=True)
                elif do_ports:
                    st.caption("No common open ports detected.")

                if r.ssl_info:
                    st.markdown("**SSL/TLS certificate:**")
                    if r.ssl_info.get("verified"):
                        issuer = r.ssl_info.get("issuer", {}).get("organizationName", "Unknown")
                        subject_cn = r.ssl_info.get("subject", {}).get("commonName", "Unknown")
                        days_left = r.ssl_info.get("days_until_expiry")
                        st.write(f"- Subject CN: `{subject_cn}`")
                        st.write(f"- Issuer: `{issuer}`")
                        st.write(f"- Valid until: `{r.ssl_info.get('not_after')}`"
                                  + (f" ({days_left} days left)" if days_left is not None else ""))
                        st.write(f"- TLS version: `{r.ssl_info.get('tls_version')}`")
                        st.write(f"- Cipher suite: `{r.ssl_info.get('cipher_suite')}`")
                        if r.ssl_info.get("expiry_warning"):
                            st.error("⚠️ Certificate expires in under 30 days!")
                        sans = r.ssl_info.get("subject_alt_names", [])
                        if sans:
                            st.write(f"- SANs: {', '.join(sans[:10])}" + (" ..." if len(sans) > 10 else ""))
                    elif r.ssl_info.get("error"):
                        st.warning(f"Could not retrieve certificate: {r.ssl_info['error']}")

                if r.error:
                    st.info(r.error)

    # ---- Tab 3: Technologies rollup ----
    with tab3:
        tech_counts = {}
        tech_advisories = {}
        for r in results:
            for t in r.technologies:
                tech_counts[t["name"]] = tech_counts.get(t["name"], 0) + 1
                tech_advisories[t["name"]] = t["advisory"]

        if not tech_counts:
            st.info("No technologies were fingerprinted across scanned hosts.")
        else:
            st.caption(
                "Best-effort fingerprinting from response headers and page markup. "
                "This is not a CVE database — treat advisories as a starting point for manual review."
            )
            for name, count in sorted(tech_counts.items(), key=lambda kv: -kv[1]):
                hosts = [r.subdomain for r in results if any(t["name"] == name for t in r.technologies)]
                with st.container(border=True):
                    c1, c2 = st.columns([1, 3])
                    c1.markdown(f"**{name}**  \n`{count} host(s)`")
                    c2.write(tech_advisories[name])
                    c2.caption("Found on: " + ", ".join(hosts[:8]) + (" ..." if len(hosts) > 8 else ""))

    # ---- Tab 4: Compare scans ----
    with tab4:
        if len(st.session_state.history) < 2:
            st.info("Run at least two scans (same or different domains) in this session to compare results.")
        else:
            labels = [f"{h['domain']} · {h['timestamp']}" for h in st.session_state.history]
            c1, c2 = st.columns(2)
            idx_a = c1.selectbox("Scan A", range(len(labels)), format_func=lambda i: labels[i],
                                  index=len(labels) - 2)
            idx_b = c2.selectbox("Scan B", range(len(labels)), format_func=lambda i: labels[i],
                                  index=len(labels) - 1)

            scan_a = st.session_state.history[idx_a]
            scan_b = st.session_state.history[idx_b]
            subs_a = {r.subdomain: r for r in scan_a["results"]}
            subs_b = {r.subdomain: r for r in scan_b["results"]}

            new_hosts = sorted(set(subs_b) - set(subs_a))
            removed_hosts = sorted(set(subs_a) - set(subs_b))
            common_hosts = sorted(set(subs_a) & set(subs_b))
            risk_changed = [
                (h, subs_a[h].risk_level, subs_b[h].risk_level)
                for h in common_hosts if subs_a[h].risk_level != subs_b[h].risk_level
            ]

            m1, m2, m3 = st.columns(3)
            m1.metric("New subdomains", len(new_hosts))
            m2.metric("Disappeared", len(removed_hosts))
            m3.metric("Risk level changed", len(risk_changed))

            if new_hosts:
                st.markdown("**🆕 New since Scan A:**")
                st.write(", ".join(f"`{h}`" for h in new_hosts))
            if removed_hosts:
                st.markdown("**🚫 No longer resolving:**")
                st.write(", ".join(f"`{h}`" for h in removed_hosts))
            if risk_changed:
                st.markdown("**⚠️ Risk level changes:**")
                for h, old, new in risk_changed:
                    arrow = "🔺" if ["clean", "low", "medium", "high", "critical"].index(new) > \
                                    ["clean", "low", "medium", "high", "critical"].index(old) else "🔻"
                    st.write(f"{arrow} `{h}`: {old} → {new}")
            if not new_hosts and not removed_hosts and not risk_changed:
                st.success("No meaningful differences between these two scans.")

elif st.session_state.get("domain_scanned") is None:
    st.info("👈 Enter a domain and click **Start scan** to begin.")
    with st.container(border=True):
        st.markdown(
            "**What this tool does**\n\n"
            "- Brute-forces common subdomain prefixes + checks certificate-transparency logs\n"
            "- Probes each live host over HTTP/HTTPS and grades its security headers (A–F)\n"
            "- Scans a safe set of common TCP ports\n"
            "- Pulls TLS certificate details and flags near-expiry certs\n"
            "- Fingerprints common web technologies and surfaces relevant advisories\n"
            "- Scores overall risk per host and lets you compare scans over time"
        )
      
