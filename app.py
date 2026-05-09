import streamlit as st
import requests
import json

st.set_page_config(
    page_title="crypto-vuln-detector",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Source+Sans+3:wght@300;400;600;700&family=Source+Serif+4:wght@600;700&display=swap');

    html, body, [class*="css"] { font-family: 'Source Sans 3', sans-serif; }
    .stApp { background-color: #f4f4f4; }
    .main .block-container { padding: 0 !important; max-width: 100% !important; }

    .topbar { background: #1b2a4a; padding: 7px 24px; display: flex; gap: 10px; align-items: center; }
    .tb-btn { font-size: 10.5px; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase; padding: 5px 14px; border-radius: 3px; cursor: pointer; border: none; }
    .tb-outline { background: transparent; border: 1.5px solid #4a6fa5; color: #a8c4e0; }
    .tb-green { background: #2d6a2d; color: #fff; }
    .tb-teal { background: #1a5f7a; color: #fff; }
    .tb-red { background: #8b1a1a; color: #fff; }

    .site-header { background: #ffffff; border-bottom: 3px solid #1b2a4a; padding: 14px 24px; display: flex; align-items: center; justify-content: space-between; }
    .header-left { display: flex; align-items: center; gap: 14px; }
    .shield-logo { width: 52px; height: 52px; background: #1b2a4a; border-radius: 50%; display: flex; align-items: center; justify-content: center; border: 3px solid #c8a84b; flex-shrink: 0; }
    .header-title { font-family: 'Source Serif 4', serif; font-size: 17px; font-weight: 700; color: #1b2a4a; letter-spacing: -0.2px; }
    .header-subtitle { font-size: 10px; font-weight: 600; letter-spacing: 1.5px; text-transform: uppercase; color: #4a6fa5; margin-top: 2px; }

    .site-nav { background: #1b2a4a; padding: 0 24px; display: flex; }
    .nav-item { font-size: 12.5px; font-weight: 600; color: #ffffff; padding: 10px 16px; border-bottom: 3px solid #c8a84b; letter-spacing: 0.3px; }

    .hero { background: linear-gradient(135deg, #0d1b35 0%, #1b2a4a 40%, #0a3d5c 100%); padding: 2.5rem 24px; position: relative; overflow: hidden; }
    .hero-grid { position: absolute; top: 0; left: 0; width: 100%; height: 100%; background-image: linear-gradient(rgba(72,130,180,0.08) 1px, transparent 1px), linear-gradient(90deg, rgba(72,130,180,0.08) 1px, transparent 1px); background-size: 30px 30px; }
    .hero-content { position: relative; z-index: 1; display: flex; align-items: center; justify-content: space-between; }
    .hero-tag { display: inline-block; background: #c8a84b; color: #1b2a4a; font-size: 9.5px; font-weight: 700; letter-spacing: 2px; text-transform: uppercase; padding: 4px 12px; border-radius: 2px; margin-bottom: 12px; }
    .hero-title { font-family: 'Source Serif 4', serif; font-size: 22px; font-weight: 700; color: #ffffff; line-height: 1.25; margin-bottom: 8px; }
    .hero-desc { font-size: 12px; color: #a8c4e0; line-height: 1.6; max-width: 500px; }
    .hero-stats { display: flex; flex-direction: column; gap: 8px; align-items: flex-end; }
    .hero-stat { background: rgba(255,255,255,0.07); border: 1px solid rgba(200,168,75,0.3); border-radius: 6px; padding: 10px 16px; text-align: center; min-width: 110px; }
    .hero-stat-value { font-family: 'Source Serif 4', serif; font-size: 20px; font-weight: 700; color: #c8a84b; }
    .hero-stat-label { font-size: 9px; color: #a8c4e0; text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }

    .breadcrumb { background: #e8edf4; padding: 7px 24px; font-size: 11px; color: #4a6fa5; border-bottom: 1px solid #d0d8e8; }
    .breadcrumb-current { color: #1b2a4a; font-weight: 600; }

    .content-area { padding: 1.5rem 24px; display: flex; flex-direction: column; gap: 1.2rem; }

    .panel { background: #fff; border: 1px solid #d0d8e8; border-top: 4px solid #1b2a4a; border-radius: 4px; }
    .panel-danger { border-top-color: #8b1a1a; }
    .panel-header { padding: 1rem 1.4rem; border-bottom: 1px solid #eef0f5; display: flex; align-items: center; gap: 10px; }
    .panel-icon { width: 30px; height: 30px; background: #e8edf4; border-radius: 4px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
    .panel-title { font-size: 13px; font-weight: 700; color: #1b2a4a; text-transform: uppercase; letter-spacing: 0.5px; }
    .panel-subtitle { font-size: 11px; color: #6b7f9e; margin-top: 1px; }

    .upload-zone { border: 2px dashed #b0bdd4; border-radius: 4px; padding: 2rem; text-align: center; background: #f8f9fc; margin: 1.2rem 1.4rem; }
    .upload-zone-title { font-size: 13px; font-weight: 600; color: #1b2a4a; margin-bottom: 4px; }
    .upload-zone-sub { font-size: 11px; color: #6b7f9e; }

    .stButton > button { background: #1b2a4a !important; color: #fff !important; border: none !important; font-size: 12px !important; font-weight: 700 !important; letter-spacing: 1px !important; text-transform: uppercase !important; padding: 9px 24px !important; border-radius: 3px !important; width: 100%; }
    .stButton > button:hover { background: #243a63 !important; }
    .stButton > button:disabled { background: #b0bdd4 !important; color: #fff !important; }

    .results-banner { background: #8b1a1a; padding: 10px 1.4rem; display: flex; align-items: center; justify-content: space-between; }
    .banner-text { font-size: 12px; font-weight: 700; color: #fff; text-transform: uppercase; letter-spacing: 0.5px; }
    .banner-badge { background: #fff; color: #8b1a1a; font-size: 10px; font-weight: 700; padding: 3px 10px; border-radius: 2px; }

    .scores-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; background: #d0d8e8; }
    .score-box { background: #fff; padding: 1.2rem 1.4rem; }
    .score-label { font-size: 9.5px; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; color: #6b7f9e; margin-bottom: 8px; }
    .score-value { font-size: 28px; font-weight: 700; line-height: 1; }
    .score-pill { display: inline-block; font-size: 9px; font-weight: 700; padding: 3px 9px; border-radius: 2px; margin-top: 7px; letter-spacing: 0.8px; text-transform: uppercase; }
    .pill-critical { background: #fde8e8; color: #8b1a1a; }
    .pill-info { background: #e8edf4; color: #1b2a4a; }

    .metrics-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1px; background: #d0d8e8; }
    .metric-box { background: #f8f9fc; padding: 1rem 1.4rem; display: flex; align-items: center; gap: 12px; }
    .metric-icon { width: 36px; height: 36px; background: #e8edf4; border-radius: 4px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
    .metric-value { font-size: 20px; font-weight: 700; color: #1b2a4a; }
    .metric-label { font-size: 10px; color: #6b7f9e; text-transform: uppercase; letter-spacing: 1px; }

    .vuln-item { padding: 1rem 1.4rem; border-bottom: 1px solid #f0f2f7; display: grid; grid-template-columns: auto 1fr auto; gap: 12px; align-items: start; }
    .vuln-item:last-child { border-bottom: none; }
    .vuln-tag { font-size: 9px; font-weight: 700; letter-spacing: 1.2px; text-transform: uppercase; padding: 4px 8px; border-radius: 2px; white-space: nowrap; }
    .tag-prng { background: #fde8e8; color: #8b1a1a; }
    .tag-timing { background: #fde8e8; color: #8b1a1a; }
    .tag-memory { background: #f3e8fd; color: #5b21b6; }
    .tag-params { background: #fef3cd; color: #854f0b; }
    .vuln-message { font-size: 12px; color: #2c3e5a; }
    .vuln-meta { font-size: 10.5px; color: #6b7f9e; margin-top: 3px; }
    .vuln-reco { margin-top: 6px; font-size: 11px; color: #1a5f7a; background: #e8f4f8; padding: 5px 10px; border-left: 3px solid #1a5f7a; }
    .sev-badge { font-size: 9px; font-weight: 700; padding: 3px 8px; border-radius: 2px; text-transform: uppercase; letter-spacing: 0.5px; white-space: nowrap; }
    .sev-critical { background: #8b1a1a; color: #fff; }
    .sev-high { background: #854f0b; color: #fff; }
    .sev-medium { background: #5b21b6; color: #fff; }

    .no-vuln { background: #f0fff4; border: 1px solid #b7ebc8; border-radius: 4px; padding: 1.5rem; text-align: center; color: #2d6a2d; font-size: 13px; font-weight: 600; margin: 1.4rem; }

    .site-footer { background: #1b2a4a; padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; margin-top: 1.5rem; }
    .footer-text { font-size: 10px; color: #4a6fa5; }
    .footer-status { display: flex; align-items: center; gap: 5px; }
    .status-dot { width: 6px; height: 6px; border-radius: 50%; background: #2d6a2d; }
    .status-label { font-size: 10px; color: #a8c4e0; }

    div[data-testid="stFileUploader"] { padding: 0; }
    div[data-testid="stFileUploader"] label { display: none; }
    section[data-testid="stFileUploaderDropzone"] { background: transparent; border: none; padding: 0; }
</style>
""", unsafe_allow_html=True)


def severity_color(s):
    return {"Faible": "#2d6a2d", "Moyen": "#854f0b", "Eleve": "#8b1a1a", "Critique": "#8b1a1a"}.get(s, "#1b2a4a")

def vuln_tag_class(t):
    return {"weak_prng": "tag-prng", "timing_leak": "tag-timing", "memory_leak": "tag-memory", "weak_params": "tag-params"}.get(t, "tag-prng")

def vuln_tag_label(t):
    return {"weak_prng": "Weak PRNG", "timing_leak": "Timing Leak", "memory_leak": "Memory Leak", "weak_params": "Weak Parameters"}.get(t, t)

def sev_class(s):
    return {"Critique": "sev-critical", "Eleve": "sev-critical", "Elevée": "sev-critical", "Moyen": "sev-high", "Faible": "sev-medium"}.get(s, "sev-critical")


st.markdown("""
<div class="topbar">
    <button class="tb-btn tb-outline">Post-Quantum Security</button>
    <button class="tb-btn tb-green">Secure by Design</button>
    <button class="tb-btn tb-teal">NIST Standards</button>
    <button class="tb-btn tb-red">Report a Vulnerability</button>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="site-header">
    <div class="header-left">
        <div class="shield-logo">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="#c8a84b" stroke-width="1.8">
                <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"/>
            </svg>
        </div>
        <div>
            <div class="header-title">crypto-vuln-detector — Vulnerability Detection Platform</div>
            <div class="header-subtitle">Post-Quantum Cryptography — Static Analysis and Machine Learning</div>
        </div>
    </div>
    <div style="font-size:11px;color:#6b7f9e;text-align:right;">
        <div style="font-weight:700;color:#1b2a4a;font-size:12px;">Model Performance</div>
        <div>F1-Score: 0.92 &nbsp;|&nbsp; AUC-ROC: 0.86</div>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="site-nav">
    <div class="nav-item">File Analysis</div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="hero">
    <div class="hero-grid"></div>
    <div class="hero-content">
        <div>
            <div class="hero-tag">Post-Quantum Cryptography</div>
            <div class="hero-title">Cryptographic Vulnerability<br>Detection Platform</div>
            <div class="hero-desc">
                Analyze source files from McEliece, HQC and Classic McEliece 6688128.
                Detect weak PRNG usage, timing leaks, memory leaks, and weak parameters
                using static analysis combined with a Random Forest machine learning model.
            </div>
        </div>
        <div class="hero-stats">
            <div class="hero-stat">
                <div class="hero-stat-value">585</div>
                <div class="hero-stat-label">Training Samples</div>
            </div>
            <div class="hero-stat">
                <div class="hero-stat-value">4</div>
                <div class="hero-stat-label">Vulnerability Types</div>
            </div>
            <div class="hero-stat">
                <div class="hero-stat-value">92%</div>
                <div class="hero-stat-label">F1-Score</div>
            </div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="breadcrumb">
    Home / <span class="breadcrumb-current">File Analysis</span>
</div>
""", unsafe_allow_html=True)

st.markdown('<div class="content-area">', unsafe_allow_html=True)

st.markdown("""
<div class="panel">
    <div class="panel-header">
        <div class="panel-icon">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#1b2a4a" stroke-width="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                <polyline points="14 2 14 8 20 8"/>
            </svg>
        </div>
        <div>
            <div class="panel-title">Submit Source File for Analysis</div>
            <div class="panel-subtitle">Supported file types: Python (.py) &nbsp;|&nbsp; C source (.c) &nbsp;|&nbsp; C header (.h)</div>
        </div>
    </div>
    <div class="upload-zone">
        <div class="upload-zone-title">Drag and drop your source file here</div>
        <div class="upload-zone-sub">Supported schemes: McEliece — HQC — Classic McEliece 6688128</div>
    </div>
</div>
""", unsafe_allow_html=True)

uploaded_file = st.file_uploader(
    "Upload file",
    type=["py", "c", "h"],
    label_visibility="collapsed"
)

col1, col2, col3 = st.columns([1, 1, 1])
with col2:
    analyze_btn = st.button("Run Analysis", disabled=uploaded_file is None)

if analyze_btn and uploaded_file:
    with st.spinner("Running analysis pipeline..."):
        try:
            files = {"file": (uploaded_file.name, uploaded_file.getvalue())}
            response = requests.post("http://127.0.0.1:8000/analyze", files=files)
            result = response.json()

            severity     = result.get("severity", "Inconnu")
            global_score = result.get("global_score", 0)
            ml_score     = result.get("ml_score", 0)
            static_score = result.get("static_score", 0)
            vulns        = result.get("vulnerabilities", [])
            metrics      = result.get("metrics", {})
            s_color      = severity_color(severity)

            st.markdown(f"""
            <div class="panel panel-danger" style="margin-top:0;">
                <div class="results-banner">
                    <div class="banner-text">Analysis Results — {uploaded_file.name}</div>
                    <div class="banner-badge">{len(vulns)} Vulnerabilit{'y' if len(vulns)==1 else 'ies'} Detected</div>
                </div>
                <div class="scores-grid">
                    <div class="score-box">
                        <div class="score-label">Global Risk Score</div>
                        <div class="score-value" style="color:{s_color};">{global_score}%</div>
                        <div class="score-pill pill-critical">{severity}</div>
                    </div>
                    <div class="score-box">
                        <div class="score-label">Machine Learning Score</div>
                        <div class="score-value" style="color:#1b2a4a;">{ml_score}%</div>
                        <div class="score-pill pill-info">Random Forest</div>
                    </div>
                    <div class="score-box">
                        <div class="score-label">Static Analysis Score</div>
                        <div class="score-value" style="color:#1b2a4a;">{static_score}%</div>
                        <div class="score-pill pill-info">Pattern Matching</div>
                    </div>
                    <div class="score-box">
                        <div class="score-label">Vulnerabilities Found</div>
                        <div class="score-value" style="color:#8b1a1a;">{len(vulns)}</div>
                        <div class="score-pill {'pill-critical' if len(vulns) > 0 else 'pill-info'}">
                            {'Requires Attention' if len(vulns) > 0 else 'All Clear'}
                        </div>
                    </div>
                </div>
                <div class="metrics-row">
                    <div class="metric-box">
                        <div class="metric-icon">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#1b2a4a" stroke-width="1.8">
                                <polyline points="4 17 10 11 4 5"/>
                                <line x1="12" y1="19" x2="20" y2="19"/>
                            </svg>
                        </div>
                        <div>
                            <div class="metric-value">{metrics.get('loc', 0)}</div>
                            <div class="metric-label">Lines of Code</div>
                        </div>
                    </div>
                    <div class="metric-box">
                        <div class="metric-icon">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#1b2a4a" stroke-width="1.8">
                                <line x1="21" y1="10" x2="3" y2="10"/>
                                <line x1="21" y1="6" x2="3" y2="6"/>
                                <line x1="21" y1="14" x2="3" y2="14"/>
                                <line x1="21" y1="18" x2="3" y2="18"/>
                            </svg>
                        </div>
                        <div>
                            <div class="metric-value">{metrics.get('comment_lines', 0)}</div>
                            <div class="metric-label">Comment Lines</div>
                        </div>
                    </div>
                    <div class="metric-box">
                        <div class="metric-icon">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#1b2a4a" stroke-width="1.8">
                                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                                <line x1="12" y1="9" x2="12" y2="13"/>
                                <line x1="12" y1="17" x2="12.01" y2="17"/>
                            </svg>
                        </div>
                        <div>
                            <div class="metric-value">{metrics.get('dangerous_func_count', 0)}</div>
                            <div class="metric-label">Dangerous Function Calls</div>
                        </div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("""
            <div class="panel panel-danger">
                <div class="panel-header">
                    <div class="panel-icon" style="background:#fde8e8;">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#8b1a1a" stroke-width="2">
                            <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"/>
                        </svg>
                    </div>
                    <div>
                        <div class="panel-title" style="color:#8b1a1a;">Detected Vulnerabilities</div>
                        <div class="panel-subtitle">Listed by severity — with remediation guidance</div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

            if not vulns:
                st.markdown("""
                <div class="no-vuln">
                    No vulnerabilities detected — this file appears to be secure.
                </div>
                """, unsafe_allow_html=True)
            else:
                for v in vulns:
                    tag_cls = vuln_tag_class(v.get("type", ""))
                    tag_lbl = vuln_tag_label(v.get("type", ""))
                    sev_cls = sev_class(v.get("severity", ""))
                    st.markdown(f"""
                    <div class="vuln-item">
                        <span class="vuln-tag {tag_cls}">{tag_lbl}</span>
                        <div>
                            <div class="vuln-message">{v.get('message', '')}</div>
                            <div class="vuln-meta">Line {v.get('line', 0)} &nbsp;—&nbsp; {uploaded_file.name}</div>
                            <div class="vuln-reco">{v.get('recommendation', '')}</div>
                        </div>
                        <span class="sev-badge {sev_cls}">{v.get('severity', '')}</span>
                    </div>
                    """, unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

            st.download_button(
                label="Download Full Report (JSON)",
                data=json.dumps(result, indent=2, ensure_ascii=False),
                file_name=f"cryptoscan_report_{uploaded_file.name}.json",
                mime="application/json"
            )

        except Exception as e:
            st.error(f"Connection error: {e}")
            st.info("Make sure the API is running: python api.py")

st.markdown("</div>", unsafe_allow_html=True)

st.markdown("""
<div class="site-footer">
    <div class="footer-text">crypto-vuln-detector v1.0 — Post-Quantum Cryptography Vulnerability Detection Platform</div>
    <div class="footer-status">
        <div class="status-dot"></div>
        <div class="status-label">API connected — port 8000</div>
    </div>
</div>
""", unsafe_allow_html=True)
