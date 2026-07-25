"""Visual theme: dark ops-console styling for the recon dashboard."""

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');

:root {
    --bg:        #0B0E11;
    --panel:     #12161C;
    --panel-2:   #171C24;
    --line:      #232A33;
    --text:      #E8ECF1;
    --muted:     #7A8699;
    --accent:    #00D9C0;
    --accent-dim:#0A3D38;
    --good:      #2ED573;
    --warn:      #FFC048;
    --bad:       #FF4757;
}

html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
.stApp { background: radial-gradient(circle at 15% 0%, #101720 0%, var(--bg) 45%); }

code, .mono, [data-testid="stMetricValue"] {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Hide default chrome for a tighter console feel */
#MainMenu, footer { visibility: hidden; }
header[data-testid="stHeader"] { background: transparent; }

/* ---- Hero ---- */
.recon-hero {
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
}
.recon-hero::after {
    content: "";
    position: absolute;
    top: -50%; right: -10%;
    width: 260px; height: 260px;
    border-radius: 50%;
    background: radial-gradient(circle, var(--accent-dim) 0%, transparent 70%);
    pointer-events: none;
}
.recon-sweep {
    width: 46px; height: 46px;
    border-radius: 50%;
    border: 2px solid var(--accent);
    position: relative;
    flex-shrink: 0;
    background: conic-gradient(from 0deg, var(--accent) 0deg, transparent 70deg);
    animation: sweep 2.2s linear infinite;
}
.recon-sweep::before {
    content: "";
    position: absolute;
    inset: 8px;
    border-radius: 50%;
    background: var(--panel);
}
@keyframes sweep { to { transform: rotate(360deg); } }
@media (prefers-reduced-motion: reduce) {
    .recon-sweep { animation: none; }
}
.recon-hero h1 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--text);
    margin: 0;
    letter-spacing: -0.01em;
}
.recon-hero p {
    color: var(--muted);
    margin: 4px 0 0 0;
    font-size: 0.92rem;
}

/* ---- Grade badge ---- */
.grade-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 34px; height: 34px;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
    font-size: 1.05rem;
}
.grade-A { background: rgba(46,213,115,0.15); color: var(--good); border: 1px solid rgba(46,213,115,0.35); }
.grade-B { background: rgba(46,213,115,0.10); color: #7BE0A0; border: 1px solid rgba(46,213,115,0.25); }
.grade-C { background: rgba(255,192,72,0.15); color: var(--warn); border: 1px solid rgba(255,192,72,0.35); }
.grade-D { background: rgba(255,113,72,0.15); color: #FF8A5C; border: 1px solid rgba(255,113,72,0.35); }
.grade-F { background: rgba(255,71,87,0.15); color: var(--bad); border: 1px solid rgba(255,71,87,0.35); }
.grade-NA { background: rgba(122,134,153,0.12); color: var(--muted); border: 1px solid var(--line); }

/* ---- Risk pill ---- */
.risk-pill {
    display: inline-block;
    padding: 3px 11px;
    border-radius: 999px;
    font-size: 0.76rem;
    font-weight: 600;
    font-family: 'JetBrains Mono', monospace;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}
.risk-clean    { background: rgba(46,213,115,0.14); color: var(--good); }
.risk-low      { background: rgba(46,213,115,0.10); color: #7BE0A0; }
.risk-medium   { background: rgba(255,192,72,0.14); color: var(--warn); }
.risk-high     { background: rgba(255,113,72,0.14); color: #FF8A5C; }
.risk-critical { background: rgba(255,71,87,0.16); color: var(--bad); }
.risk-unknown  { background: rgba(122,134,153,0.12); color: var(--muted); }

/* ---- Tech chip ---- */
.tech-chip {
    display: inline-block;
    padding: 2px 9px;
    margin: 2px 4px 2px 0;
    border-radius: 6px;
    background: var(--panel-2);
    border: 1px solid var(--line);
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.76rem;
    color: var(--text);
}

/* ---- Card ---- */
.recon-card {
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 16px 18px;
    background: var(--panel);
}

/* Streamlit metric tiles */
[data-testid="stMetric"] {
    background: var(--panel);
    border: 1px solid var(--line);
    border-radius: 12px;
    padding: 14px 16px;
}
[data-testid="stMetricLabel"] { color: var(--muted); }

/* Buttons */
.stButton > button, .stDownloadButton > button {
    border-radius: 8px;
    font-weight: 600;
    border: 1px solid var(--line);
}
.stButton > button[kind="primary"] {
    background: var(--accent);
    color: #04211D;
    border: none;
}
.stButton > button[kind="primary"]:hover {
    background: #10E8CE;
}

/* Tabs */
.stTabs [data-baseweb="tab"] { font-family: 'JetBrains Mono', monospace; }

/* Divider */
hr { border-color: var(--line) !important; }
</style>
"""


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
