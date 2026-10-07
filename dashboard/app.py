"""
dashboard/app.py (v2)
-----------------------
New in v2:
- Self-healing: if train.py/simulate.py were never run (e.g. a fresh clone,
  or a cloud deploy where the artifacts weren't committed), the dashboard
  runs the full pipeline itself on first load instead of just erroring out.
  Training the ensemble takes ~25s and the simulation ~5s, so this adds a
  one-time ~30s wait on a cold start, then is cached for the session.
- A "Live replay" mode that steps through the simulation log on a timer,
  so it reads like a live SOC feed rather than a static chart.
- Model comparison table (RF vs HistGB vs ensemble) and a feature
  importance panel for explainability.
"""

import json
import os
import subprocess
import sys
import time

import pandas as pd
import streamlit as st

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUTS = os.path.join(ROOT, "outputs")
MODELS = os.path.join(ROOT, "models")

ACTION_COLORS = {
    "ALLOW": "#3fb950",
    "STEP_UP_VERIFICATION": "#4098d7",
    "RESTRICT": "#d29922",
    "QUARANTINE": "#f85149",
}
ACTION_ORDER = ["ALLOW", "STEP_UP_VERIFICATION", "RESTRICT", "QUARANTINE"]

st.set_page_config(page_title="Adaptive Zero Trust IPS for IoT", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
    .stApp { background-color: #0d1117; }
    section[data-testid="stSidebar"] { background-color: #010409; }
    div[data-testid="stMetric"] {
        background-color: #161b22; border: 1px solid #30363d;
        border-radius: 6px; padding: 12px 16px;
    }
    div[data-testid="stMetricLabel"] { color: #8b949e; }
    h1, h2, h3 { color: #e6edf3; font-family: 'IBM Plex Mono', monospace; }
    .action-chip {
        display: inline-block; padding: 2px 10px; border-radius: 4px;
        font-family: monospace; font-size: 0.85em; font-weight: 600; color: #0d1117;
    }
</style>
""", unsafe_allow_html=True)


def artifacts_present() -> bool:
    needed = [
        os.path.join(OUTPUTS, "simulation_log.csv"),
        os.path.join(OUTPUTS, "simulation_summary.json"),
        os.path.join(OUTPUTS, "model_eval.json"),
    ]
    return all(os.path.exists(p) for p in needed)


@st.cache_resource(show_spinner=False)
def ensure_artifacts():
    """Self-healing bootstrap: train + simulate once per app instance if the
    artifacts aren't already on disk (e.g. a fresh clone or a cloud deploy
    where models/outputs weren't committed)."""
    if artifacts_present():
        return "already-present"

    os.makedirs(OUTPUTS, exist_ok=True)
    os.makedirs(MODELS, exist_ok=True)
    with st.spinner("First run: training the detection engine (~30s, cached after this)..."):
        subprocess.run([sys.executable, os.path.join(ROOT, "train.py")], check=True, cwd=ROOT)
        subprocess.run([sys.executable, os.path.join(ROOT, "simulate.py")], check=True, cwd=ROOT)
    return "bootstrapped"


@st.cache_data
def load_artifacts():
    log_df = pd.read_csv(os.path.join(OUTPUTS, "simulation_log.csv"), parse_dates=["timestamp"])
    with open(os.path.join(OUTPUTS, "simulation_summary.json")) as f:
        summary = json.load(f)
    with open(os.path.join(OUTPUTS, "model_eval.json")) as f:
        eval_report = json.load(f)
    return log_df, summary, eval_report


ensure_artifacts()
log_df, summary, eval_report = load_artifacts()

st.title("🛡️ Adaptive Zero Trust Framework — IoT Intrusion Prevention")
st.caption(
    "Continuous per-device trust scoring (classifier + anomaly detector + behavioral baselining) "
    "and adaptive policy enforcement. Final-year project: *An Adaptive Zero Trust Framework for "
    "Intelligent Intrusion Prevention in IoT Networks.*"
)

# ---------------------------------------------------------------- KPI row
ens = eval_report["model_comparison"]["ensemble"]
c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Ensemble Accuracy", f"{ens['accuracy']*100:.1f}%")
c2.metric("Ensemble ROC-AUC", f"{ens['roc_auc']:.3f}")
c3.metric("Devices Monitored", summary["devices_simulated"])
c4.metric("Ever Quarantined", summary["devices_ever_quarantined"])
c5.metric("Avg. Events to Quarantine", summary["mean_own_events_to_quarantine_after_first_attack"])
c6.metric("Over-restriction Rate", f"{summary['benign_traffic_over_restricted_rate']*100:.1f}%")

st.divider()

# ---------------------------------------------------------- Live replay mode
mode = st.radio("View mode", ["Static dashboard", "▶ Live replay"], horizontal=True, label_visibility="collapsed")

if mode == "▶ Live replay":
    st.subheader("Live SOC feed (replaying the simulation)")
    devices = sorted(log_df["device_id"].unique())
    sel_device = st.selectbox("Follow device", devices, index=devices.index("hub-01") if "hub-01" in devices else 0)
    speed = st.slider("Playback speed (events/sec)", 1, 20, 8)
    dev_df = log_df[log_df["device_id"] == sel_device].sort_values("tick").reset_index(drop=True)

    placeholder = st.empty()
    chart_placeholder = st.empty()
    if st.button("▶ Play", type="primary"):
        history = []
        for i, row in dev_df.iterrows():
            history.append(row["trust_score"])
            color = ACTION_COLORS.get(row["policy_action"], "#8b949e")
            with placeholder.container():
                k1, k2, k3, k4 = st.columns(4)
                k1.metric("Tick", int(row["tick"]))
                k2.metric("Trust score", f"{row['trust_score']:.1f}")
                k3.metric("Requests/min", f"{row['requests_per_min']:.0f}")
                st.markdown(
                    f"<span class='action-chip' style='background-color:{color}'>{row['policy_action']}</span> "
                    f"&nbsp; {row['reason']}",
                    unsafe_allow_html=True,
                )
            chart_placeholder.line_chart(pd.Series(history, name="trust_score"), height=220)
            time.sleep(1.0 / speed)
    else:
        st.info("Click ▶ Play to replay this device's trust score evolving event by event.")

else:
    # ---------------------------------------------------------- Trust timeline
    left, right = st.columns([2, 1])

    with left:
        st.subheader("Device trust score over time")
        devices = sorted(log_df["device_id"].unique())
        selected = st.selectbox("Device", devices, index=devices.index("hub-01") if "hub-01" in devices else 0)

        dev_df = log_df[log_df["device_id"] == selected].sort_values("tick")
        st.line_chart(dev_df.set_index("timestamp")[["trust_score"]].rename(columns={"trust_score": selected}), height=300)

        campaign = dev_df[dev_df["scripted_campaign_active"]]
        if len(campaign):
            st.caption(
                f"Scripted attack campaign: **{campaign['timestamp'].iloc[0]}** to **{campaign['timestamp'].iloc[-1]}** "
                f"— types seen: {', '.join(sorted(campaign['true_attack_category'].unique()))}"
            )

        st.subheader("Policy action timeline")
        action_counts_over_time = (
            dev_df.groupby([pd.Grouper(key="timestamp", freq="1min"), "policy_action"]).size().unstack(fill_value=0)
        )
        for a in ACTION_ORDER:
            if a not in action_counts_over_time.columns:
                action_counts_over_time[a] = 0
        st.area_chart(action_counts_over_time[ACTION_ORDER], height=220)

    with right:
        st.subheader("Fleet status (latest)")
        latest = (
            log_df.sort_values("tick").groupby("device_id").last().reset_index()
            [["device_id", "archetype", "criticality", "trust_score", "policy_action"]].sort_values("trust_score")
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
    st.subheader("Model comparison (held-out test set)")
    comp_rows = []
    for name, m in eval_report["model_comparison"].items():
        comp_rows.append({
            "model": name, "accuracy": round(m["accuracy"], 4), "precision": round(m["precision"], 4),
            "recall": round(m["recall"], 4), "f1": round(m["f1"], 4), "roc_auc": round(m["roc_auc"], 4),
        })
    st.dataframe(pd.DataFrame(comp_rows), width='stretch', hide_index=True)

    m1, m2 = st.columns(2)
    with m1:
        cm = eval_report["confusion_matrix"]
        cm_df = pd.DataFrame(cm, index=["Actual: Normal", "Actual: Attack"], columns=["Pred: Normal", "Pred: Attack"])
        st.markdown("**Confusion matrix (ensemble)**")
        st.dataframe(cm_df, width='stretch')
    with m2:
        st.markdown("**Top feature importances (RandomForest)**")
        fi_df = pd.DataFrame(eval_report["feature_importances"]).set_index("feature")
        st.bar_chart(fi_df, height=260)

    st.subheader("Policy action breakdown across the whole simulation")
    action_totals = pd.Series(summary["policy_action_counts"]).reindex(ACTION_ORDER).fillna(0)
    st.bar_chart(action_totals, height=220)

    with st.expander("About the synthetic IoT telemetry features"):
        st.write(
            "`requests_per_min` and `avg_payload_bytes` are synthetically generated — archetype-conditioned "
            "baselines perturbed in a direction consistent with how each attack family actually manifests "
            "(DoS/Probe spike request rate and shrink payloads; R2L/U2R cause smaller, stealthier deviations) "
            "— documented this way rather than passed off as captured packets. See README.md for the full "
            "data-provenance note."
        )

st.caption("Data: NSL-KDD + simulated IoT device fleet. Final-year project prototype.")
