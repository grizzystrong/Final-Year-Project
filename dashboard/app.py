"""
dashboard/app.py
-----------------
Streamlit dashboard for the Adaptive Zero Trust Framework prototype.
Reads the artifacts produced by train.py and simulate.py -- it does not
run any model inference itself, so it stays fast and simple to deploy
(e.g. Streamlit Community Cloud, straight from the GitHub repo).

Run:
    streamlit run dashboard/app.py
"""

import json
import os

import pandas as pd
import streamlit as st

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUTS = os.path.join(ROOT, "outputs")

ACTION_COLORS = {
    "ALLOW": "#3fb950",
    "STEP_UP_VERIFICATION": "#4098d7",
    "RESTRICT": "#d29922",
    "QUARANTINE": "#f85149",
}
ACTION_ORDER = ["ALLOW", "STEP_UP_VERIFICATION", "RESTRICT", "QUARANTINE"]

st.set_page_config(
    page_title="Adaptive Zero Trust IPS for IoT",
    page_icon="🛡️",
    layout="wide",
)

st.markdown("""
<style>
    .stApp { background-color: #0d1117; }
    section[data-testid="stSidebar"] { background-color: #010409; }
    div[data-testid="stMetric"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 12px 16px;
    }
    div[data-testid="stMetricLabel"] { color: #8b949e; }
    h1, h2, h3 { color: #e6edf3; font-family: 'IBM Plex Mono', monospace; }
    .action-chip {
        display: inline-block; padding: 2px 10px; border-radius: 4px;
        font-family: monospace; font-size: 0.85em; font-weight: 600;
        color: #0d1117;
    }
</style>
""", unsafe_allow_html=True)


@st.cache_data
def load_artifacts():
    log_path = os.path.join(OUTPUTS, "simulation_log.csv")
    summary_path = os.path.join(OUTPUTS, "simulation_summary.json")
    eval_path = os.path.join(OUTPUTS, "model_eval.json")

    if not (os.path.exists(log_path) and os.path.exists(summary_path) and os.path.exists(eval_path)):
        return None, None, None

    log_df = pd.read_csv(log_path, parse_dates=["timestamp"])
    with open(summary_path) as f:
        summary = json.load(f)
    with open(eval_path) as f:
        eval_report = json.load(f)
    return log_df, summary, eval_report


log_df, summary, eval_report = load_artifacts()

st.title("🛡️ Adaptive Zero Trust Framework — IoT Intrusion Prevention")
st.caption(
    "Continuous per-device trust scoring + adaptive policy enforcement, driven by a "
    "supervised + unsupervised intrusion detection engine. Prototype for the final-year "
    "project *An Adaptive Zero Trust Framework for Intelligent Intrusion Prevention in IoT Networks*."
)

if log_df is None:
    st.error(
        "No simulation artifacts found. Run the pipeline first:\n\n"
        "```\npython train.py\npython simulate.py\n```"
    )
    st.stop()

# ---------------------------------------------------------------- KPI row
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Model Accuracy", f"{eval_report['classification_report']['accuracy']*100:.1f}%")
c2.metric("ROC-AUC", f"{eval_report['roc_auc']:.3f}")
c3.metric("Devices Monitored", summary["devices_simulated"])
c4.metric("Ever Quarantined", summary["devices_ever_quarantined"])
c5.metric(
    "Avg. Events to Quarantine",
    summary["mean_own_events_to_quarantine_after_first_attack"],
    help="Mean number of a device's own malicious events observed before it was quarantined.",
)
c6.metric(
    "Over-restriction Rate",
    f"{summary['benign_traffic_over_restricted_rate']*100:.1f}%",
    help="Share of genuinely benign traffic that was still RESTRICTed or QUARANTINEd (false-positive cost).",
)

st.divider()

# ---------------------------------------------------------- Trust timeline
left, right = st.columns([2, 1])

with left:
    st.subheader("Device trust score over time")
    devices = sorted(log_df["device_id"].unique())
    selected = st.selectbox("Device", devices, index=devices.index("hub-01") if "hub-01" in devices else 0)

    dev_df = log_df[log_df["device_id"] == selected].sort_values("tick")
    chart_df = dev_df.set_index("timestamp")[["trust_score"]].rename(columns={"trust_score": selected})
    st.line_chart(chart_df, height=300)

    campaign = dev_df[dev_df["scripted_campaign_active"]]
    if len(campaign):
        st.caption(
            f"Scripted attack campaign active from **{campaign['timestamp'].iloc[0]}** to "
            f"**{campaign['timestamp'].iloc[-1]}** — attack types seen: "
            f"{', '.join(sorted(campaign['true_attack_category'].unique()))}"
        )

    st.subheader("Policy action timeline")
    action_counts_over_time = (
        dev_df.groupby([pd.Grouper(key="timestamp", freq="1min"), "policy_action"])
        .size().unstack(fill_value=0)
    )
    for a in ACTION_ORDER:
        if a not in action_counts_over_time.columns:
            action_counts_over_time[a] = 0
    st.area_chart(action_counts_over_time[ACTION_ORDER], height=220)

with right:
    st.subheader("Fleet status (latest)")
    latest = (
        log_df.sort_values("tick").groupby("device_id").last()
        .reset_index()[["device_id", "archetype", "criticality", "trust_score", "policy_action"]]
        .sort_values("trust_score")
    )

    for _, row in latest.iterrows():
        color = ACTION_COLORS.get(row["policy_action"], "#8b949e")
        st.markdown(
            f"**{row['device_id']}** · {row['archetype']} (crit. {row['criticality']:.1f})  \n"
            f"Trust: {row['trust_score']:.1f} &nbsp;"
            f"<span class='action-chip' style='background-color:{color}'>{row['policy_action']}</span>",
            unsafe_allow_html=True,
        )
        st.progress(min(max(row["trust_score"] / 100, 0.0), 1.0))

    st.subheader("Network-wide threat level")
    threat_df = log_df.sort_values("tick").drop_duplicates("tick")[["timestamp", "global_threat_level"]]
    st.area_chart(threat_df.set_index("timestamp"), height=180)

st.divider()

# ---------------------------------------------------------- Model quality
st.subheader("Intrusion detection model performance (held-out test set)")
m1, m2 = st.columns(2)

with m1:
    cm = eval_report["confusion_matrix"]
    cm_df = pd.DataFrame(cm, index=["Actual: Normal", "Actual: Attack"], columns=["Pred: Normal", "Pred: Attack"])
    st.markdown("**Confusion matrix**")
    st.dataframe(cm_df, use_container_width=True)

with m2:
    report = eval_report["classification_report"]
    rows = []
    for label in ["0", "1"]:
        if label in report:
            rows.append({
                "class": "Normal" if label == "0" else "Attack",
                "precision": round(report[label]["precision"], 3),
                "recall": round(report[label]["recall"], 3),
                "f1-score": round(report[label]["f1-score"], 3),
                "support": int(report[label]["support"]),
            })
    st.markdown("**Precision / Recall / F1**")
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

st.subheader("Policy action breakdown across the whole simulation")
action_totals = pd.Series(summary["policy_action_counts"]).reindex(ACTION_ORDER).fillna(0)
st.bar_chart(action_totals, height=220)

with st.expander("Why isn't accuracy closer to 100%?"):
    st.write(
        "The NSL-KDD test split deliberately includes attack types that never appear in the "
        "training split, to evaluate generalization to unseen threats rather than memorization. "
        "That is also exactly the scenario continuous, adaptive verification is meant for: the "
        "trust engine's unsupervised anomaly signal is designed to catch suspicious behavior the "
        "supervised classifier alone would miss."
    )

st.caption(
    "Data: NSL-KDD network intrusion benchmark, replayed through a simulated IoT device fleet "
    "(see README for the dataset/methodology note). Built as a final-year project prototype."
)
