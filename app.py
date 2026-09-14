
import streamlit as st
import pandas as pd
import numpy as np
import pickle
import os
import time
import hashlib
import sqlite3
from datetime import datetime

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

# =========================================================
# PAGE CONFIG
# =========================================================
st.set_page_config(
    page_title="SentinelAI | Cybersecurity Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =========================================================
# KDD COLUMNS
# =========================================================
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes",
    "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
    "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label"
]

feature_columns = columns[:-1]

categorical_columns = ["protocol_type", "service", "flag"]
numeric_columns = [
    col for col in feature_columns if col not in categorical_columns
]

# =========================================================
# ADVANCED UI
# =========================================================
st.markdown("""

<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 10% 0%, rgba(0, 180, 255, .12), transparent 28%),
        radial-gradient(circle at 95% 10%, rgba(150, 70, 255, .11), transparent 25%),
        linear-gradient(180deg, #05080d 0%, #080c13 55%, #05070b 100%);
}

.block-container {
    max-width: 1500px;
    padding-top: 1.2rem;
    padding-bottom: 3rem;
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0a111a 0%, #070b11 100%);
    border-right: 1px solid rgba(90, 180, 255, .13);
}

[data-testid="stSidebar"] * { color: #e7eef7; }

.soc-hero {
    position: relative;
    overflow: hidden;
    padding: 28px 32px;
    border-radius: 24px;
    background:
      linear-gradient(135deg, rgba(10, 27, 43, .97), rgba(8, 13, 22, .98));
    border: 1px solid rgba(90, 190, 255, .20);
    box-shadow: 0 0 0 1px rgba(255,255,255,.015), 0 25px 80px rgba(0,0,0,.42);
    margin-bottom: 18px;
}

.soc-hero:before {
    content: "";
    position: absolute;
    width: 420px; height: 420px;
    right: -180px; top: -240px;
    border-radius: 50%;
    border: 1px solid rgba(80,190,255,.13);
    box-shadow: 0 0 0 35px rgba(80,190,255,.025), 0 0 0 70px rgba(80,190,255,.018);
}

.hero-row {
    display:flex; justify-content:space-between; align-items:center;
    gap:20px; position:relative; z-index:1;
}

.brand-wrap { display:flex; align-items:center; gap:15px; }
.brand-shield {
    width:62px; height:62px; border-radius:18px;
    display:flex; align-items:center; justify-content:center;
    font-size:31px;
    background:linear-gradient(145deg,#102f49,#0d1825);
    border:1px solid rgba(100,205,255,.30);
    box-shadow:0 0 30px rgba(0,170,255,.12);
}

.soc-title { margin:0; font-size:32px; font-weight:800; letter-spacing:-1px; }
.soc-subtitle { margin:6px 0 0; color:#7f95aa; font-size:14px; }

.live-chip {
    padding:10px 15px; border-radius:999px;
    background:rgba(34,197,94,.08);
    border:1px solid rgba(34,197,94,.28);
    color:#65f39a; font-weight:700; font-size:12px;
    box-shadow:0 0 24px rgba(34,197,94,.08);
}

.grid-bg {
    margin-top:20px; height:5px; border-radius:99px;
    background:linear-gradient(90deg,#19d3ff,#5968ff,#bd4cff,#19d3ff);
    background-size:250% 100%;
    animation: flow 5s linear infinite;
}
@keyframes flow { from{background-position:0 0} to{background-position:250% 0} }

.section-title {
    font-size:22px; font-weight:800; margin:25px 0 13px; color:#f3f7fb;
}

.kpi {
    padding:19px 20px; min-height:118px; border-radius:18px;
    background:linear-gradient(145deg,rgba(14,24,35,.96),rgba(9,15,23,.98));
    border:1px solid rgba(130,180,220,.10);
    box-shadow:0 12px 35px rgba(0,0,0,.24);
}
.kpi-label { color:#7890a7; font-size:11px; font-weight:700; letter-spacing:1px; }
.kpi-value { font-size:29px; font-weight:800; margin-top:8px; color:#f4f8fc; }
.kpi-sub { color:#607489; font-size:11px; margin-top:5px; }
.metric-good { color:#5cf09a !important; }
.metric-danger { color:#ff6375 !important; }
.metric-blue { color:#61c8ff !important; }
.metric-purple { color:#b993ff !important; }

.panel {
    padding:18px; border-radius:18px;
    background:rgba(10,16,24,.84);
    border:1px solid rgba(130,180,220,.09);
}

.alert-card, .safe-card, .info-card {
    padding:15px 18px; border-radius:14px; margin:15px 0;
    font-weight:700;
}
.alert-card {
    background:linear-gradient(90deg,rgba(150,24,45,.34),rgba(65,12,23,.18));
    border:1px solid rgba(255,78,104,.24); color:#ff8795;
}
.safe-card {
    background:linear-gradient(90deg,rgba(18,100,58,.24),rgba(9,55,35,.15));
    border:1px solid rgba(74,222,128,.22); color:#65ef9a;
}
.info-card {
    background:linear-gradient(90deg,rgba(15,82,125,.23),rgba(10,42,70,.14));
    border:1px solid rgba(70,180,255,.18); color:#78caff;
}

.gauge-card {
    padding:20px; border-radius:18px; text-align:center;
    background:radial-gradient(circle at 50% 25%, rgba(55,170,255,.12), transparent 45%), #0a1018;
    border:1px solid rgba(90,180,255,.10);
}
.gauge {
    width:170px; height:85px; margin:8px auto 2px;
    border-radius:170px 170px 0 0;
    background:conic-gradient(from 270deg, #39e58a 0deg, #ffd166 80deg, #ff6b6b 145deg, #ff3d57 180deg, transparent 180deg);
    position:relative; overflow:hidden;
}
.gauge:after {
    content:""; position:absolute; width:126px; height:63px;
    left:22px; bottom:0; border-radius:126px 126px 0 0;
    background:#0a1018;
}
.gauge-value {
    font-size:28px; font-weight:800; margin-top:-55px; position:relative; z-index:2;
}
.gauge-label { color:#71879b; font-size:11px; margin-top:35px; letter-spacing:1px; }

.telemetry {
    padding:13px 15px; border-radius:13px; margin:7px 0;
    background:rgba(255,255,255,.025);
    border:1px solid rgba(255,255,255,.055);
}
.telemetry-row { display:flex; justify-content:space-between; gap:10px; }
.telemetry-name { color:#9aabbb; font-size:12px; }
.telemetry-value { color:#e9f2fa; font-family:'JetBrains Mono',monospace; font-size:12px; }

.command-bar {
    display:flex; gap:8px; flex-wrap:wrap; margin:10px 0 4px;
}
.cmd {
    padding:6px 10px; border-radius:7px; font-family:'JetBrains Mono',monospace;
    font-size:10px; color:#81cfff; background:#091622; border:1px solid #12334a;
}

.sidebar-brand { font-size:22px; font-weight:800; padding:8px 3px 18px; }
.sidebar-mini { color:#71869a; font-size:11px; line-height:1.7; }
div[data-testid="stFileUploader"] {
    background:rgba(9,17,27,.78); border:1px dashed rgba(80,190,255,.28);
    border-radius:16px; padding:8px;
}
.stButton > button, .stDownloadButton > button {
    border-radius:10px; font-weight:700;
    border:1px solid rgba(100,190,255,.18);
    background:#0c1723; color:#eaf4fb;
}

.stButton > button:hover { border-color:rgba(100,210,255,.55); }

.soc-divider {
    height:1px;
    background:linear-gradient(90deg, transparent, rgba(80,190,255,.25), transparent);
    margin:22px 0;
}
.status-row {
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:12px;
    padding:12px 14px;
    border-radius:12px;
    background:rgba(255,255,255,.025);
    border:1px solid rgba(255,255,255,.05);
    margin-bottom:8px;
}
.status-left { display:flex; align-items:center; gap:9px; color:#a9b9c9; font-size:12px; }
.status-dot { width:8px; height:8px; border-radius:50%; background:#45e58b; box-shadow:0 0 12px rgba(69,229,139,.65); }

.status-right { color:#eaf4fb; font-family:'JetBrains Mono',monospace; font-size:11px; }
.alert-feed{display:flex;gap:12px;align-items:flex-start;padding:13px 15px;margin:7px 0;border-radius:13px;background:rgba(255,70,90,.055);border:1px solid rgba(255,90,110,.12);}
.alert-icon{width:30px;height:30px;display:flex;align-items:center;justify-content:center;border-radius:9px;background:rgba(255,70,90,.12);color:#ff7180;font-weight:800;}
.alert-main{flex:1}.alert-top{display:flex;justify-content:space-between;align-items:center;gap:10px;}
.alert-id{color:#dce8f3;font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;}
.severity{padding:4px 7px;border-radius:6px;font-size:9px;font-weight:800;letter-spacing:.6px;}
.severity-critical,.severity-high{background:rgba(255,70,90,.13);color:#ff7180;}
.severity-medium{background:rgba(185,147,255,.12);color:#c4a8ff;}
.alert-desc{color:#e8f0f7;font-size:12px;font-weight:700;margin-top:5px;}
.alert-meta{color:#71869a;font-size:10px;margin-top:5px;}

.mini-title {
    color:#7890a7;
    font-size:10px;
    font-weight:800;
    letter-spacing:1.2px;
    margin-bottom:8px;
}

footer { visibility:hidden; }
</style>
""", unsafe_allow_html=True)


# =========================================================
# READY-STATE PERSISTENT ALERT STORE
# =========================================================
DB_FILE = "sentinelai_alerts.db"
LIVE_LOG_FILE = "logs/live_logs.csv"

def init_alert_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            event_id TEXT PRIMARY KEY,
            detected_at TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence REAL NOT NULL,
            protocol TEXT,
            service TEXT,
            flag TEXT,
            source_mode TEXT NOT NULL,
            fingerprint TEXT UNIQUE
        )
    """)
    conn.commit()
    conn.close()

def event_fingerprint(row):
    values = [str(row.get(c, "")) for c in feature_columns]
    return hashlib.sha256("|".join(values).encode("utf-8", errors="ignore")).hexdigest()

def stable_event_id(fingerprint):
    return "EVT-" + fingerprint[:10].upper()

def persist_alerts(results, source_mode):
    """Persist only attack events; duplicates are ignored safely."""
    attacks = results[results["Prediction"] == "Attack"]
    if attacks.empty:
        return 0

    conn = sqlite3.connect(DB_FILE)
    inserted = 0
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for _, row in attacks.iterrows():
        fp = event_fingerprint(row)
        event_id = stable_event_id(fp)
        try:
            conn.execute(
                """
                INSERT INTO alerts
                (event_id, detected_at, severity, confidence, protocol, service, flag, source_mode, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    now,
                    str(row.get("Severity", "HIGH")),
                    float(row.get("Confidence", 0)),
                    str(row.get("protocol_type", "")),
                    str(row.get("service", "")),
                    str(row.get("flag", "")),
                    source_mode,
                    fp,
                ),
            )
            inserted += 1
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()
    return inserted

def load_alert_history(limit=100):
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query(
        """
        SELECT event_id AS "Event ID",
               detected_at AS "Detected At",
               severity AS "Severity",
               ROUND(confidence, 2) AS "Confidence",
               protocol AS "Protocol",
               service AS "Service",
               flag AS "Flag",
               source_mode AS "Source"
        FROM alerts
        ORDER BY detected_at DESC
        LIMIT ?
        """,
        conn,
        params=(limit,),
    )
    conn.close()
    return df

init_alert_db()

# =========================================================
# MODEL
# =========================================================
@st.cache_resource
def load_model():
    with open("model.pkl", "rb") as file:
        return pickle.load(file)

try:
    model = load_model()
except Exception as e:
    st.error("Unable to load model.pkl")
    st.warning("Run: python3 train_model.py")
    st.exception(e)
    st.stop()

# =========================================================
# DATA HELPERS
# =========================================================
def load_kdd_csv(source):
    data = pd.read_csv(source, header=None)

    if data.shape[1] == len(columns):
        first_value = str(data.iloc[0, 0]).strip().lower()
        if first_value == "duration":
            data = data.iloc[1:].reset_index(drop=True)
        data.columns = columns

    elif data.shape[1] == len(feature_columns):
        data.columns = feature_columns

    else:
        raise ValueError(
            f"Invalid CSV format. Expected {len(feature_columns)} "
            f"or {len(columns)} columns, received {data.shape[1]}."
        )

    return data

def prepare_features(data):
    X = data[feature_columns].copy()

    for col in categorical_columns:
        X[col] = X[col].astype(str).str.strip()

    for col in numeric_columns:
        X[col] = pd.to_numeric(X[col], errors="coerce")

    X[numeric_columns] = X[numeric_columns].fillna(0)
    return X

def analyze_logs(data):
    X = prepare_features(data)
    predictions = model.predict(X)

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(X)
        confidence = (probabilities.max(axis=1) * 100).round(2)
    else:
        confidence = [0.0] * len(predictions)

    results = data.copy()
    results["Prediction"] = [
        "Attack" if int(p) == 1 else "Normal" for p in predictions
    ]
    results["Confidence"] = confidence
    return results

def convert_actual_labels(data):
    if "label" not in data.columns:
        return None

    labels = (
        data["label"].astype(str).str.strip().str.lower()
        .str.replace(".", "", regex=False)
    )
    return labels.apply(lambda x: 0 if x == "normal" else 1)


def add_threat_intelligence(results):
    """Add presentation-oriented severity and event identifiers."""
    results = results.copy()

    confidence = pd.to_numeric(results["Confidence"], errors="coerce").fillna(0)
    prediction = results["Prediction"].astype(str)

    severity = np.where(
        prediction.eq("Normal"),
        "INFO",
        np.where(
            confidence >= 95,
            "CRITICAL",
            np.where(confidence >= 80, "HIGH", "MEDIUM")
        )
    )
    results["Severity"] = severity
    results["Event ID"] = results.apply(
        lambda row: stable_event_id(event_fingerprint(row)),
        axis=1
    )
    return results


def risk_posture(attack_count, total, avg_confidence):
    """Heuristic dashboard score; not a calibrated probability."""
    if total <= 0:
        return 0, "LOW"

    attack_rate = attack_count / total * 100
    score = min(100, attack_rate * 0.70 + float(avg_confidence) * 0.30 * (attack_count / total))

    if score >= 70:
        label = "CRITICAL"
    elif score >= 40:
        label = "ELEVATED"
    elif score >= 15:
        label = "GUARDED"
    else:
        label = "LOW"

    return score, label


def show_severity_summary(results):
    severity_counts = (
        results["Severity"]
        .value_counts()
        .reindex(["CRITICAL", "HIGH", "MEDIUM", "INFO"], fill_value=0)
    )
    cols = st.columns(4)
    items = [
        ("CRITICAL", "metric-danger"),
        ("HIGH", "metric-danger"),
        ("MEDIUM", "metric-purple"),
        ("INFO", "metric-good"),
    ]
    for col, (level, cls) in zip(cols, items):
        with col:
            kpi(
                f"{level} EVENTS",
                f"{int(severity_counts[level]):,}",
                "AI-assigned display severity",
                cls
            )



def show_alert_feed(results, limit=8):
    """Render a compact SOC-style alert feed."""
    threats = results[results["Prediction"] == "Attack"].tail(limit).iloc[::-1]
    if threats.empty:
        st.markdown(
            '<div class="safe-card">✓ ALERT FEED | No malicious events are currently present.</div>',
            unsafe_allow_html=True
        )
        return

    for _, row in threats.iterrows():
        severity = str(row.get("Severity", "HIGH"))
        event_id = str(row.get("Event ID", "EVENT"))
        confidence = float(row.get("Confidence", 0))
        protocol = str(row.get("protocol_type", "unknown"))
        service = str(row.get("service", "unknown"))

        html = (
            '<div class="alert-feed">'
            '<div class="alert-icon">⚠</div>'
            '<div class="alert-main">'
            f'<div class="alert-top"><span class="alert-id">{event_id}</span>'
            f'<span class="severity severity-{severity.lower()}">{severity}</span></div>'
            '<div class="alert-desc">Suspicious network activity detected</div>'
            f'<div class="alert-meta">Protocol: {protocol} • Service: {service} • Confidence: {confidence:.1f}%</div>'
            '</div></div>'
        )
        st.markdown(html, unsafe_allow_html=True)


def kpi(label, value, sub="", cls=""):
    st.markdown(
        f"""<div class="kpi">
        <div class="kpi-label">{label}</div>
        <div class="kpi-value {cls}">{value}</div>
        <div class="kpi-sub">{sub}</div>
        </div>""",
        unsafe_allow_html=True
    )

# =========================================================
# HEADER
# =========================================================
st.markdown("""
<div class="soc-hero">
  <div class="hero-row">
    <div class="brand-wrap">
      <div class="brand-shield">🛡️</div>
      <div>
        <h1 class="soc-title">SentinelAI SOC</h1>
        <p class="soc-subtitle">AI Cybersecurity Log Monitoring • Threat Intelligence • Random Forest Detection</p>
      </div>
    </div>
    <div class="live-chip">● AI ENGINE ONLINE</div>
  </div>
  <div class="command-bar">
    <span class="cmd">MODEL: RANDOM_FOREST</span>
    <span class="cmd">MODE: NORMAL_VS_ATTACK</span>
    <span class="cmd">DATA: KDD_SECURITY</span>
    <span class="cmd">STATUS: OPERATIONAL</span>
  </div>
  <div class="grid-bg"></div>
</div>
""", unsafe_allow_html=True)

# =========================================================
# SIDEBAR
# =========================================================
with st.sidebar:
    st.markdown('<div class="sidebar-brand">🛡️ SentinelAI</div>',
                unsafe_allow_html=True)
    st.success("AI Engine Ready")
    st.markdown(
        '<div class="status-row"><span class="status-left"><span class="status-dot"></span>Detection engine</span><span class="status-right">ONLINE</span></div>'
        '<div class="status-row"><span class="status-left"><span class="status-dot"></span>Preprocessor</span><span class="status-right">READY</span></div>',
        unsafe_allow_html=True
    )
    st.write("**Model:** Random Forest")
    st.write("**Learning:** Supervised ML")
    st.write("**Detection:** Normal vs Attack")
    st.write("**Dataset:** KDD Network Security")
    st.markdown("---")

    mode = st.radio(
        "MONITORING MODE",
        ["📂 Log File Analysis", "🖥️ Live Log Monitoring"]
    )

    st.markdown("---")
    st.markdown(
        '<div class="sidebar-mini">'
        'AI pipeline<br>'
        'Preprocessing → Random Forest → Threat Classification<br><br>'
        'Prototype status: operational'
        '</div>',
        unsafe_allow_html=True
    )

# =========================================================
# LOG FILE ANALYSIS
# =========================================================
if mode == "📂 Log File Analysis":

    st.markdown('<div class="section-title">📂 Security Log Analysis</div>',
                unsafe_allow_html=True)

    st.markdown(
        '<div class="info-card">'
        'Upload a KDD-format cybersecurity CSV. SentinelAI will '
        'preprocess every record and classify it as Normal or Attack.'
        '</div>',
        unsafe_allow_html=True
    )

    uploaded_file = st.file_uploader(
        "Upload cybersecurity log file",
        type=["csv"]
    )

    if uploaded_file is not None:
        try:
            data = load_kdd_csv(uploaded_file)

            st.success(f"✓ {len(data):,} log records loaded successfully")

            st.markdown('<div class="section-title">📋 Log Intelligence</div>',
                        unsafe_allow_html=True)
            st.dataframe(data.head(10), width="stretch", height=310)

            with st.spinner("AI engine analyzing security events..."):
                results = add_threat_intelligence(analyze_logs(data))
            persist_alerts(results, "FILE_ANALYSIS")

            total_logs = len(results)
            attack_count = int((results["Prediction"] == "Attack").sum())
            normal_count = int((results["Prediction"] == "Normal").sum())
            threat_rate = attack_count / total_logs * 100 if total_logs else 0
            avg_confidence = results["Confidence"].mean() if total_logs else 0

            st.markdown('<div class="section-title">📊 Security Command Center</div>',
                        unsafe_allow_html=True)

            c1, c2, c3, c4 = st.columns(4)
            with c1:
                kpi("TOTAL EVENTS", f"{total_logs:,}", "Analyzed by AI", "metric-blue")
            with c2:
                kpi("NORMAL EVENTS", f"{normal_count:,}", "No threat detected", "metric-good")
            with c3:
                kpi("THREATS DETECTED", f"{attack_count:,}", "Potentially malicious", "metric-danger")
            with c4:
                kpi("THREAT RATE", f"{threat_rate:.2f}%", f"AI confidence {avg_confidence:.1f}%", "metric-danger")

            show_severity_summary(results)

            if attack_count > 0:
                st.markdown(
                    f'<div class="alert-card">🚨 SECURITY ALERT &nbsp;|&nbsp; '
                    f'{attack_count:,} potentially malicious events detected.</div>',
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    '<div class="safe-card">✓ SECURITY STATUS &nbsp;|&nbsp; '
                    'No malicious activity detected in the analyzed logs.</div>',
                    unsafe_allow_html=True
                )

            left, right = st.columns([1.0, 1.15])

            with left:
                risk, risk_label = risk_posture(attack_count, total_logs, avg_confidence)
                st.markdown('<div class="section-title">🎯 Current Risk Posture</div>',
                            unsafe_allow_html=True)
                st.markdown(
                    f"""
                    <div class="gauge-card">
                        <div class="gauge"><div class="gauge-value">{risk:.0f}%</div></div>
                        <div class="gauge-label">THREAT EXPOSURE • {risk_label}</div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            with right:
                st.markdown('<div class="section-title">📡 Security Telemetry</div>',
                            unsafe_allow_html=True)
                st.markdown(
                    f"""
                    <div class="telemetry"><div class="telemetry-row"><span class="telemetry-name">Events processed</span><span class="telemetry-value">{total_logs:,}</span></div></div>
                    <div class="telemetry"><div class="telemetry-row"><span class="telemetry-name">Threat events</span><span class="telemetry-value">{attack_count:,}</span></div></div>
                    <div class="telemetry"><div class="telemetry-row"><span class="telemetry-name">Average AI confidence</span><span class="telemetry-value">{avg_confidence:.2f}%</span></div></div>
                    """,
                    unsafe_allow_html=True
                )

            left, right = st.columns([1.1, 1])

            with left:
                st.markdown('<div class="section-title">📈 Threat Distribution</div>',
                            unsafe_allow_html=True)
                chart_data = pd.DataFrame({
                    "Normal": [normal_count],
                    "Attack": [attack_count]
                })
                st.bar_chart(chart_data, height=300)

            with right:
                st.markdown('<div class="section-title">🎯 AI Confidence</div>',
                            unsafe_allow_html=True)
                confidence_bins = pd.cut(
                    results["Confidence"],
                    bins=[0, 50, 75, 90, 100],
                    labels=["Low", "Medium", "High", "Very High"],
                    include_lowest=True
                ).value_counts().sort_index()
                st.bar_chart(confidence_bins, height=300)

            actual_labels = convert_actual_labels(data)

            if actual_labels is not None:
                predicted_labels = results["Prediction"].apply(
                    lambda x: 1 if x == "Attack" else 0
                )

                accuracy = accuracy_score(actual_labels, predicted_labels)
                precision = precision_score(actual_labels, predicted_labels, zero_division=0)
                recall = recall_score(actual_labels, predicted_labels, zero_division=0)
                f1 = f1_score(actual_labels, predicted_labels, zero_division=0)

                st.markdown('<div class="section-title">🎯 Model Performance</div>',
                            unsafe_allow_html=True)

                m1, m2, m3, m4 = st.columns(4)
                with m1: kpi("ACCURACY", f"{accuracy*100:.2f}%", "Overall correctness", "metric-good")
                with m2: kpi("PRECISION", f"{precision*100:.2f}%", "Attack predictions", "metric-blue")
                with m3: kpi("RECALL", f"{recall*100:.2f}%", "Threat detection", "metric-blue")
                with m4: kpi("F1 SCORE", f"{f1*100:.2f}%", "Balanced performance", "metric-good")

                cm = confusion_matrix(actual_labels, predicted_labels)
                cm_df = pd.DataFrame(
                    cm,
                    index=["Actual Normal", "Actual Attack"],
                    columns=["Predicted Normal", "Predicted Attack"]
                )

                with st.expander("🔬 View Confusion Matrix"):
                    st.dataframe(cm_df, width="stretch")

            st.markdown('<div class="section-title">🧬 Attack Surface Intelligence</div>',
                        unsafe_allow_html=True)
            attack_rows = results[results["Prediction"] == "Attack"].copy()

            ai1, ai2 = st.columns(2)
            with ai1:
                attack_protocols = (
                    attack_rows["protocol_type"].astype(str).value_counts().head(8)
                    if len(attack_rows) else pd.Series(dtype=int)
                )
                st.markdown('<div class="panel">', unsafe_allow_html=True)
                st.caption("ATTACKS BY PROTOCOL")
                if len(attack_protocols):
                    st.bar_chart(attack_protocols, height=220)
                else:
                    st.info("No attack telemetry available.")
                st.markdown('</div>', unsafe_allow_html=True)

            with ai2:
                severity_counts = (
                    results["Severity"]
                    .value_counts()
                    .reindex(["CRITICAL", "HIGH", "MEDIUM", "INFO"], fill_value=0)
                )
                st.markdown('<div class="panel">', unsafe_allow_html=True)
                st.caption("SEVERITY DISTRIBUTION")
                st.bar_chart(severity_counts, height=220)
                st.markdown('</div>', unsafe_allow_html=True)

            st.markdown('<div class="soc-divider"></div>', unsafe_allow_html=True)

            st.markdown('<div class="section-title">🌐 Traffic Intelligence</div>',
                        unsafe_allow_html=True)
            tc1, tc2 = st.columns(2)

            with tc1:
                protocol_counts = data["protocol_type"].astype(str).value_counts().head(8)
                st.markdown('<div class="panel">', unsafe_allow_html=True)
                st.caption("PROTOCOL TELEMETRY")
                st.bar_chart(protocol_counts, height=230)
                st.markdown('</div>', unsafe_allow_html=True)

            with tc2:
                service_counts = data["service"].astype(str).value_counts().head(8)
                st.markdown('<div class="panel">', unsafe_allow_html=True)
                st.caption("TOP SERVICES")
                st.bar_chart(service_counts, height=230)
                st.markdown('</div>', unsafe_allow_html=True)

            st.markdown('<div class="section-title">🚨 Threat Detection Results</div>',
                        unsafe_allow_html=True)

            feed_left, feed_right = st.columns([1.25, 1])
            with feed_left:
                st.markdown('<div class="mini-title">LIVE AI ALERT FEED</div>', unsafe_allow_html=True)
                show_alert_feed(results)
            with feed_right:
                st.markdown('<div class="mini-title">EXECUTIVE STATUS</div>', unsafe_allow_html=True)
                st.markdown(
                    f'<div class="panel">'
                    f'<div class="status-row"><span class="status-left"><span class="status-dot"></span>Detection engine</span><span class="status-right">ONLINE</span></div>'
                    f'<div class="status-row"><span class="status-left"><span class="status-dot"></span>Events analyzed</span><span class="status-right">{total_logs:,}</span></div>'
                    f'<div class="status-row"><span class="status-left"><span class="status-dot"></span>Threat rate</span><span class="status-right">{threat_rate:.2f}%</span></div>'
                    f'<div class="status-row"><span class="status-left"><span class="status-dot"></span>AI confidence</span><span class="status-right">{avg_confidence:.1f}%</span></div>'
                    f'</div>', unsafe_allow_html=True
                )

            attacks = results[results["Prediction"] == "Attack"]

            if len(attacks):
                st.warning(f"{len(attacks):,} suspicious records detected")
                priority_cols = [
                    "Event ID", "Severity", "Prediction", "Confidence",
                    "protocol_type", "service", "flag", "src_bytes", "dst_bytes"
                ]
                priority_cols = [c for c in priority_cols if c in attacks.columns]
                st.dataframe(attacks[priority_cols], width="stretch", height=420)
            else:
                st.info("No suspicious records detected.")

            with st.expander("📄 View Complete AI Analysis"):
                st.dataframe(results, width="stretch", height=450)

            csv_data = results.to_csv(index=False).encode("utf-8")
            st.download_button(
                "⬇️ Export Threat Analysis Report",
                csv_data,
                "sentinelai_threat_analysis.csv",
                "text/csv"
            )

        except Exception as e:
            st.error("Error while processing the CSV file.")
            st.exception(e)

# =========================================================
# LIVE LOG MONITORING
# =========================================================
else:

    st.markdown('<div class="section-title">🖥️ Live Security Operations</div>',
                unsafe_allow_html=True)

    st.markdown(
        '<div class="info-card">'
        'Continuous analysis of the monitored cybersecurity log file. '
        'The trained Random Forest engine classifies incoming records '
        'and updates the security dashboard.'
        '</div>',
        unsafe_allow_html=True
    )

    log_file = "logs/live_logs.csv"

    if not os.path.exists(log_file):
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        pd.DataFrame(columns=columns).to_csv(log_file, index=False, header=False)
        st.info("Live log source initialized. Waiting for incoming KDD-format log records.")

    c1, c2, c3, c4 = st.columns([1, 1.15, 1.15, 1.5])

    with c1:
        refresh = st.button("🔄 Refresh Logs")

    with c2:
        auto_refresh = st.checkbox("Continuous monitoring", value=True)

    with c3:
        demo_stream = st.checkbox("🎬 Demo live stream", value=True)

    with c4:
        st.caption(f"Last dashboard check: {datetime.now().strftime('%H:%M:%S')}")

    try:
        # ---------------------------------------------------------
        # OPTIONAL DEMO STREAM
        # ---------------------------------------------------------
        # This uses the bundled test logs as a transparent, local
        # simulation of incoming events. It does not claim raw
        # network packet capture. Real KDD-format logs can still be
        # written to logs/live_logs.csv when Demo live stream is off.
        if demo_stream:
            demo_data = load_kdd_csv("test_logs.csv")
            if len(demo_data):
                demo_pos = st.session_state.get("demo_stream_pos", 0)
                next_row = demo_data.iloc[[demo_pos % len(demo_data)]].copy()
                existing = load_kdd_csv(log_file) if os.path.exists(log_file) else pd.DataFrame(columns=columns)

                # Keep the demo stream compact while allowing the dashboard
                # to visibly update as new records arrive.
                if len(existing) >= 30:
                    existing = existing.tail(29).copy()
                updated = pd.concat([existing, next_row], ignore_index=True)
                updated.to_csv(log_file, index=False, header=False)
                st.session_state["demo_stream_pos"] = (demo_pos + 1) % len(demo_data)
                st.caption("🎬 Demo stream is feeding bundled KDD test events into the live monitor.")

        live_data = load_kdd_csv(log_file)

        if len(live_data) == 0:
            st.info("No live events available. Turn on Demo live stream or add KDD-format records to logs/live_logs.csv.")
            st.stop()

        results = add_threat_intelligence(analyze_logs(live_data))
        persist_alerts(results, "LIVE_MONITOR")

        total = len(results)
        attacks = int((results["Prediction"] == "Attack").sum())
        normal = int((results["Prediction"] == "Normal").sum())
        threat_rate = attacks / total * 100 if total else 0
        avg_confidence = results["Confidence"].mean() if total else 0

        st.markdown(
            f'<div class="safe-card">🟢 MONITORING ACTIVE &nbsp;|&nbsp; '
            f'{total:,} events analyzed &nbsp;|&nbsp; '
            f'Average AI confidence: {avg_confidence:.1f}%</div>',
            unsafe_allow_html=True
        )

        st.markdown('<div class="section-title">📊 Live Security Status</div>',
                    unsafe_allow_html=True)

        c1, c2, c3, c4 = st.columns(4)
        with c1: kpi("EVENTS", f"{total:,}", "Current log stream", "metric-blue")
        with c2: kpi("NORMAL", f"{normal:,}", "Safe events", "metric-good")
        with c3: kpi("THREATS", f"{attacks:,}", "Suspicious events", "metric-danger")
        with c4: kpi("THREAT RATE", f"{threat_rate:.2f}%", "Current risk level", "metric-danger")

        show_severity_summary(results)

        if attacks:
            st.markdown(
                f'<div class="alert-card">🚨 LIVE SECURITY ALERT &nbsp;|&nbsp; '
                f'{attacks:,} suspicious events detected.</div>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                '<div class="safe-card">✓ LIVE STATUS &nbsp;|&nbsp; '
                'No active threats detected.</div>',
                unsafe_allow_html=True
            )

        left, right = st.columns([1.0, 1.15])

        with left:
            risk, risk_label = risk_posture(attacks, total, avg_confidence)
            st.markdown('<div class="section-title">🎯 Live Risk Posture</div>',
                        unsafe_allow_html=True)
            st.markdown(
                f"""
                <div class="gauge-card">
                    <div class="gauge"><div class="gauge-value">{risk:.0f}%</div></div>
                    <div class="gauge-label">CURRENT EXPOSURE • {risk_label}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with right:
            st.markdown('<div class="section-title">📡 Live Telemetry</div>',
                        unsafe_allow_html=True)
            st.markdown(
                f"""
                <div class="telemetry"><div class="telemetry-row"><span class="telemetry-name">Events monitored</span><span class="telemetry-value">{total:,}</span></div></div>
                <div class="telemetry"><div class="telemetry-row"><span class="telemetry-name">Threats detected</span><span class="telemetry-value">{attacks:,}</span></div></div>
                <div class="telemetry"><div class="telemetry-row"><span class="telemetry-name">AI confidence</span><span class="telemetry-value">{avg_confidence:.2f}%</span></div></div>
                """,
                unsafe_allow_html=True
            )

        left, right = st.columns([1.15, 1])

        with left:
            st.markdown('<div class="section-title">📈 Live Threat Distribution</div>',
                        unsafe_allow_html=True)
            chart = pd.DataFrame({
                "Normal": [normal],
                "Attack": [attacks]
            })
            st.bar_chart(chart, height=320)

        with right:
            st.markdown('<div class="section-title">🧠 Detection Confidence</div>',
                        unsafe_allow_html=True)
            st.line_chart(
                results["Confidence"].reset_index(drop=True),
                height=320
            )

        st.markdown('<div class="section-title">🚨 Recent Threat Activity</div>',
                    unsafe_allow_html=True)

        feed_left, feed_right = st.columns([1.25, 1])
        with feed_left:
            st.markdown('<div class="mini-title">LATEST AI ALERTS</div>', unsafe_allow_html=True)
            show_alert_feed(results)
        with feed_right:
            st.markdown('<div class="mini-title">MONITORING STATUS</div>', unsafe_allow_html=True)
            st.markdown(
                f'<div class="panel">'
                f'<div class="status-row"><span class="status-left"><span class="status-dot"></span>Monitoring</span><span class="status-right">ACTIVE</span></div>'
                f'<div class="status-row"><span class="status-left"><span class="status-dot"></span>Events monitored</span><span class="status-right">{total:,}</span></div>'
                f'<div class="status-row"><span class="status-left"><span class="status-dot"></span>Threat rate</span><span class="status-right">{threat_rate:.2f}%</span></div>'
                f'<div class="status-row"><span class="status-left"><span class="status-dot"></span>AI confidence</span><span class="status-right">{avg_confidence:.1f}%</span></div>'
                f'</div>', unsafe_allow_html=True
            )

        threat_logs = results[results["Prediction"] == "Attack"]

        if len(threat_logs):
            st.warning(f"{len(threat_logs):,} potentially malicious events")
            priority_cols = [
                "Event ID", "Severity", "Prediction", "Confidence",
                "protocol_type", "service", "flag", "src_bytes", "dst_bytes"
            ]
            priority_cols = [c for c in priority_cols if c in threat_logs.columns]
            st.dataframe(threat_logs[priority_cols].tail(20), width="stretch", height=420)
        else:
            st.info("No malicious events detected.")

        with st.expander("📡 View Latest Monitored Events"):
            st.dataframe(results.tail(20), width="stretch", height=360)

        csv_data = results.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Export Live Threat Report",
            csv_data,
            "sentinelai_live_threat_report.csv",
            "text/csv"
        )

        if auto_refresh:
            time.sleep(2)
            st.rerun()

    except Exception as e:
        st.error("Error while reading live logs.")
        st.exception(e)


# =========================================================
# PERSISTENT ALERT HISTORY
# =========================================================
st.markdown('<div class="section-title">🗄️ Persistent Alert History</div>',
            unsafe_allow_html=True)
history_df = load_alert_history(100)

if history_df.empty:
    st.info("No persisted security alerts yet. Detected attacks will appear here automatically.")
else:
    h1, h2 = st.columns([1.3, 1])
    with h1:
        st.dataframe(history_df, width="stretch", height=320)
    with h2:
        st.markdown(
            f'<div class="panel">'
            f'<div class="mini-title">INCIDENT STORE</div>'
            f'<div class="status-row"><span class="status-left"><span class="status-dot"></span>Persistent database</span><span class="status-right">ONLINE</span></div>'
            f'<div class="status-row"><span class="status-left"><span class="status-dot"></span>Stored alerts</span><span class="status-right">{len(history_df):,}</span></div>'
            f'<div class="status-row"><span class="status-left"><span class="status-dot"></span>Storage</span><span class="status-right">SQLite</span></div>'
            f'</div>',
            unsafe_allow_html=True
        )
    history_csv = history_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Export Persistent Alert History",
        history_csv,
        "sentinelai_alert_history.csv",
        "text/csv",
        key="export_alert_history"
    )

# =========================================================
# FOOTER
# =========================================================
st.markdown("---")
st.markdown('<div class="soc-divider"></div>', unsafe_allow_html=True)
fc1, fc2, fc3 = st.columns(3)
with fc1:
    st.caption("MODEL  •  RANDOM FOREST")
with fc2:
    st.caption("TASK  •  NORMAL vs ATTACK")
with fc3:
    st.caption("PIPELINE  •  PREPROCESS → CLASSIFY → REPORT")

st.caption(
    "SENTINELAI • AI-Based Cybersecurity Log Monitoring & Threat Detection "
    "• Random Forest Machine Learning"
)
