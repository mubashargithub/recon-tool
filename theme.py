"""Visual theme: dual-mode (dark/light) ops-console styling for the recon dashboard."""

# --------------------------------------------------------------------------
# Token systems
# --------------------------------------------------------------------------
# Dark: deep console black with a teal signature accent — the original
# identity of the tool, kept as-is because it already reads as "scanner
# console" without leaning on a generic AI-purple/near-black default.
#
# Light: not an inverted dark theme. It's a considered daylight palette —
# cool slate-white background, true white panels for depth, and the same
# teal accent darkened just enough to hold contrast on white.

DARK_TOKENS = {
    "bg":         "#0B0E11",
    "bg-grad":    "#101720",
    "panel":      "#12161C",
    "panel-2":    "#171C24",
    "line":       "#232A33",
    "text":       "#E8ECF1",
    "muted":      "#7A8699",
    "accent":     "#00D9C0",
    "accent-ink": "#04211D",
    "accent-dim": "#0A3D38",
    "accent-hover": "#10E8CE",
    "good":       "#2ED573",
    "good-soft":  "#7BE0A0",
    "warn":       "#FFC048",
    "bad":        "#FF4757",
    "bad-soft":   "#FF8A5C",
    "shadow":     "0 4px 14px rgba(0,0,0,0.45)",
}

LIGHT_TOKENS = {
    "bg":         "#F5F7F9",
    "bg-grad":    "#EAF3F1",
    "panel":      "#FFFFFF",
    "panel-2":    "#F1F4F7",
    "line":       "#DCE2E8",
    "text":       "#1B222B",
    "muted":      "#5B6672",
    "accent":     "#00A896",
    "accent-ink": "#FFFFFF",
    "accent-dim": "#CFF0EA",
    "accent-hover": "#009585",
    "good":       "#1F9D5C",
    "good-soft":  "#2E7D4F",
    "warn":       "#B8790A",
    "bad":        "#E13849",
    "bad-soft":   "#D65C3C",
    "shadow":     "0 4px 14px rgba(20,30,40,0.08)",
}


def build_css(mode: str = "dark") -> str:
    """Return the full <style> block for the given mode ('dark' or 'light')."""
    t = LIGHT_TOKENS if mode == "light" else DARK_TOKENS
    header_bg = t["panel"]

    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');

:root {{
    --bg:          {t['bg']};
    --bg-grad:     {t['bg-grad']};
    --panel:       {t['panel']};
    --panel-2:     {t['panel-2']};
    --line:        {t['line']};
    --text:        {t['text']};
    --muted:       {t['muted']};
    --accent:      {t['accent']};
    --accent-ink:  {t['accent-ink']};
    --accent-dim:  {t['accent-dim']};
    --accent-hover:{t['accent-hover']};
    --good:        {t['good']};
    --good-soft:   {t['good-soft']};
    --warn:        {t['warn']};
    --bad:         {t['bad']};
    --bad-soft:    {t['bad-soft']};
    --shadow:      {t['shadow']};
}}

html, body, [class*="css"] {{ font-family: 'Inter', sans-serif; }}
.stApp {{
    background: radial-gradient(circle at 15% 0%, var(--bg-grad) 0%, var(--bg) 45%);
    color: var(--text);
}}

/* Push page content below the solid header so nothing hides underneath it */
.main .block-container {{ padding-top: 1.5rem; max-width: 1200px; }}

code, .mono, [data-testid="stMetricValue"] {{
    font-family: 'JetBrains Mono', monospace !important;
}}

/* Hide default chrome for a tighter console feel */
#MainMenu, footer {{ visibility: hidden; }}

/* ---- Fix the top toolbar (Share / star / edit / GitHub / >> icons) ----
   These sit in Streamlit's header, which we don't want fully invisible —
   just restyled to match the active theme so every icon stays legible on
   both light and dark host backgrounds (browser chrome, embeds, etc). */
header[data-testid="stHeader"] {{
    background: {header_bg} !important;
    border-bottom: 1px solid var(--line);
}}
header[data-testid="stHeader"] * {{
    color: var(--text) !important;
    fill: var(--text) !important;
    opacity: 1 !important;
}}
header[data-testid="stHeader"] svg {{
    stroke: var(--text) !important;
}}
header[data-testid="stHeader"] button:hover {{
    background: var(--panel-2) !important;
    border-radius: 6px;
}}
[data-testid="stToolbarActions"] button,
[data-testid="stToolbarActions"] a {{
    color: var(--text) !important;
}}
[data-testid="stToolbarActions"] button:hover,
[data-testid="stToolbarActions"] a:hover {{
    background: var(--panel-2) !important;
}}
[data-testid="stDecoration"],
[data-testid="stStatusWidget"] {{
    background: transparent !important;
}}

/* ---- Sidebar ---- */
section[data-testid="stSidebar"] {{
    background: var(--panel);
    border-right: 1px solid var(--line);
}}

/* ---- Sidebar-open control ---- */
[data-testid="collapsedControl"] {{
    background: var(--accent) !important;
    border-radius: 10px !important;
    box-shadow: 0 0 0 4px var(--accent-dim), var(--shadow) !important;
    animation: nudge 1.6s ease-in-out infinite;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    min-width: 40px !important;
    min-height: 40px !important;
}}
[data-testid="collapsedControl"] svg {{
    fill: var(--accent-ink) !important;
    stroke: var(--accent-ink) !important;
    width: 22px !important;
    height: 22px !important;
}}
@keyframes nudge {{
    0%, 100% {{ transform: translateX(0); }}
    50% {{ transform: translateX(4px); }}
}}
@media (prefers-reduced-motion: reduce) {{
    [data-testid="collapsedControl"] {{ animation: none; }}
}}

/* ---- Mobile "open settings here" banner ---- */
.mobile-sidebar-hint {{
    display: none;
}}
@media (max-width: 640px) {{
    .mobile-sidebar-hint {{
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 12px 14px;
        margin-bottom: 14px;
        border-radius: 10px;
        border: 1px solid var(--accent-dim);
        background: color-mix(in srgb, var(--accent) 8%, transparent);
        color: var(--text);
        font-size: 0.88rem;
        line-height: 1.35;
    }}
    .mobile-sidebar-hint .arrow-icon {{
        flex-shrink: 0;
        width: 26px; height: 26px;
        border-radius: 7px;
        background: var(--accent);
        color: var(--accent-ink);
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 700;
        animation: nudge 1.6s ease-in-out infinite;
    }}
}}

/* ---- Hero ---- */
.recon-hero {{
    display: flex;
    align-items: center;
    gap: 18px;
    padding: 22px 26px;
    border: 1px solid var(--line);
    border-radius: 14px;
    background: linear-gradient(135deg, var(--panel) 0%, var(--panel-2) 100%);
    margin-bottom: 6px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
}}
.recon-hero::after {{
    content: "";
    position: absolute;
    top: -50%; right: -10%;
    width: 260px; height: 260px;
    border-radius: 50%;
    background: radial-gradient(circle, var(--accent-dim) 0%, transparent 70%);
    pointer-events: none;
}}
.recon-sweep {{
    width: 46px; height: 46px;
    border-radius: 50%;
    border: 2px solid var(--accent);
    position: relative;
    flex-shrink: 0;
    background: conic-gradient(from 0deg, var(--accent) 0deg, transparent 70deg);
    animation: sweep 2.2s linear infinite;
}}
.recon-sweep::before {{
    content: "";
    position: absolute;
    inset: 8px;
    border-radius: 50%;
    background: var(--panel);
}}
@keyframes sweep {{ to {{ transform: rotate(360deg); }} }}
@media (prefers-reduced-motion: reduce) {{
    .recon-sweep {{ animation: none; }}
}}
.recon-hero h1 {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--text);
    margin: 0;
    letter-spacing: -0.01em;
}}
.recon-hero p {{
    color: var(--muted);
    margin: 4px 0 0 0;
    font-size: 0.92rem;
}}

/* ---- Grade badge ---- */
.grade-badge {{
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 34px; height: 34px;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
    font-size: 1.05rem;
}}
.grade-A {{ background: color-mix(in srgb, var(--good) 15%, transparent); color: var(--good); border: 1px solid color-mix(in srgb, var(--good) 35%, transparent); }}
.grade-B {{ background: color-mix(in srgb, var(--good) 10%, transparent); color: var(--good-soft); border: 1px solid color-mix(in srgb, var(--good) 25%, transparent); }}
.grade-C {{ background: color-mix(in srgb, var(--warn) 15%, transparent); color: var(--warn); border: 1px solid color-mix(in srgb, var(--warn) 35%, transparent); }}
.grade-D {{ background: color-mix(in srgb, var(--bad-soft) 15%, transparent); color: var(--bad-soft); border: 1px solid color-mix(in srgb, var(--bad-soft) 35%, transparent); }}
.grade-F {{ background: color-mix(in srgb, var(--bad) 15%, transparent); color: var(--bad); border: 1px solid color-mix(in srgb, var(--bad) 35%, transparent); }}
.grade-NA {{ background: color-mix(in srgb, var(--muted) 12%, transparent); color: var(--muted); border: 1px solid var(--line); }}

/* ---- Risk pill ---- */
.risk-pill {{
    display: inline-block;
    padding: 3px 11px;
    border-radius: 999px;
    font-size: 0.76rem;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}}
.risk-clean    {{ background: color-mix(in srgb, var(--good) 14%, transparent); color: var(--good); }}
.risk-low      {{ background: color-mix(in srgb, var(--good) 10%, transparent); color: var(--good-soft); }}
.risk-medium   {{ background: color-mix(in srgb, var(--warn) 14%, transparent); color: var(--warn); }}
.risk-high     {{ background: color-mix(in srgb, var(--bad-soft) 14%, transparent); color: var(--bad-soft); }}
.risk-critical {{ background: color-mix(in srgb, var(--bad) 16%, transparent); color: var(--bad); }}
.risk-unknown  {{ background: color-mix(in srgb, var(--muted) 12%, transparent); color: var(--muted); }}

/* ---- Tech chip ---- */
.tech-chip {{
    display: inline-block;
    padding: 2px 9px;
    margin: 2px 4px 2px 0;
    border-radius: 6px;
    background: var(--panel-2);
    border: 1px solid var(--line);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.76rem;
    color: var(--text);
}}

/* ---- Card ---- */
.recon-card {{
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 16px 18px;
    background: var(--panel);
}}

/* Streamlit metric tiles */
[data-testid="stMetric"] {{
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 14px 16px;
    box-shadow: var(--shadow);
}}
[data-testid="stMetricLabel"] {{ color: var(--muted); }}
[data-testid="stMetricValue"] {{ color: var(--text); }}

/* Generic containers / expanders pick up the panel surface */
div[data-testid="stExpander"] {{
    border: 1px solid var(--line);
    border-radius: 12px;
    background: var(--panel);
}}
div[data-testid="stVerticalBlockBorderWrapper"] {{
    border-color: var(--line) !important;
}}

/* Inputs */
.stTextInput input, .stTextArea textarea, .stSelectbox [data-baseweb="select"] {{
    background: var(--panel-2) !important;
    color: var(--text) !important;
    border-color: var(--line) !important;
}}

/* Buttons */
.stButton > button, .stDownloadButton > button {{
    border-radius: 8px;
    font-weight: 600;
    border: 1px solid var(--line);
    color: var(--text);
    background: var(--panel-2);
    transition: background 0.15s ease, transform 0.1s ease;
}}
.stButton > button:hover, .stDownloadButton > button:hover {{
    transform: translateY(-1px);
}}
.stButton > button[kind="primary"] {{
    background: var(--accent);
    color: var(--accent-ink);
    border: none;
}}
.stButton > button[kind="primary"]:hover {{
    background: var(--accent-hover);
}}

/* Tabs */
.stTabs [data-baseweb="tab"] {{ font-family: 'JetBrains Mono', monospace; color: var(--muted); }}
.stTabs [aria-selected="true"] {{ color: var(--accent) !important; }}
.stTabs [data-baseweb="tab-highlight"] {{ background-color: var(--accent) !important; }}

/* Divider */
hr {{ border-color: var(--line) !important; }}

/* ---- Mobile responsiveness ---- */
@media (max-width: 640px) {{
    .recon-hero {{
        flex-direction: column;
        align-items: flex-start;
        padding: 16px 16px;
        gap: 10px;
    }}
    .recon-hero h1 {{ font-size: 1.15rem; }}
    .recon-hero p {{ font-size: 0.82rem; }}
    .recon-sweep {{ width: 36px; height: 36px; }}

    [data-testid="stMetric"] {{ padding: 10px 12px; }}
    [data-testid="stMetricValue"] {{ font-size: 1.15rem !important; }}

    .stButton > button, .stDownloadButton > button {{
        min-height: 44px;
        font-size: 0.92rem;
    }}

    .main .block-container {{ padding-left: 0.9rem; padding-right: 0.9rem; }}
}}

/* ---- Small-tablet tightening ---- */
@media (min-width: 641px) and (max-width: 900px) {{
    .main .block-container {{ padding-left: 1.2rem; padding-right: 1.2rem; }}
}}
</style>
"""


# Backwards-compatible default export (dark mode), so any existing code
# importing CSS directly keeps working exactly as before.
CSS = build_css("dark")


def grade_badge(grade: str) -> str:
    g = grade if grade in ("A", "B", "C", "D", "F") else "NA"
    label = grade if grade in ("A", "B", "C", "D", "F") else "–"
    return f'<span class="grade-badge grade-{g}">{label}</span>'


def risk_pill(level: str, score: int = None) -> str:
    level = level if level in ("clean", "low", "medium", "high", "critical") else "unknown"
    text = level.upper() if score is None else f"{level.upper()} · {score}"
    return f'<span class="risk-pill risk-{level}">{text}</span>'


def tech_chips(technologies: list) -> str:
    if not technologies:
        return '<span class="mono" style="color:var(--muted); font-size:0.85rem;">No technologies fingerprinted</span>'
    chips = []
    for t in technologies:
        label = t["name"] + (f" {t['version']}" if t.get("version") else "")
        chips.append(f'<span class="tech-chip">{label}</span>')
    return "".join(chips)
