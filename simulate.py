"""
simulate.py
-----------
Ties the three components together into a running adaptive zero-trust
simulation:

    traffic event -> IDS scores -> TrustEngine update -> PolicyEngine decision

Rather than mechanically replaying the raw NSL-KDD test set (whose overall
attack rate is ~57% -- unrealistically high for a demo of *normal* network
operation punctuated by intrusions), each simulated device is given a
scripted scenario: a mostly-benign baseline, one attack campaign (sampled
from real, held-out malicious traffic, never seen during training) that
starts at a staggered point on the shared timeline, and a cooldown period
afterward. This mirrors how these frameworks are actually evaluated in the
literature (attack-scenario replay) and makes the trust-score dynamics --
the drop during an attack and the gradual recovery after -- visible in the
dashboard instead of being washed out by nonstop malicious traffic.

Output:
    outputs/simulation_log.csv       one row per simulated traffic event
    outputs/simulation_summary.json  aggregate stats for the dashboard/report

Usage:
    python simulate.py
"""

import json
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(__file__))

import joblib
import numpy as np
import pandas as pd

from src.preprocessing import load_raw_data, assign_devices, DEVICE_FLEET
from src.ids_model import IntrusionDetectionEngine
from src.trust_engine import TrustEngine
from src.policy_engine import AdaptivePolicyEngine

DATA_DIR = "data"
MODELS_DIR = "models"
OUTPUTS_DIR = "outputs"
SEED = 42

STAGGER_GAP = 40      # ticks between each device's attack campaign starting
BASELINE_LEAD = 100   # ticks of calm before the first device is attacked
CAMPAIGN_LEN = 25     # ticks each attack campaign lasts
COOLDOWN_TAIL = 80    # ticks of calm after the last campaign ends


def build_scenario_timeline(test_df: pd.DataFrame, seed: int = SEED) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    normal_pool = test_df[test_df["is_attack"] == 0].reset_index(drop=True)
    attack_pool = test_df[test_df["is_attack"] == 1].reset_index(drop=True)

    fleet = DEVICE_FLEET
    n_devices = len(fleet)
    total_ticks = BASELINE_LEAD + (n_devices - 1) * STAGGER_GAP + CAMPAIGN_LEN + COOLDOWN_TAIL

    attack_start = {d["device_id"]: BASELINE_LEAD + i * STAGGER_GAP for i, d in enumerate(fleet)}

    rows = []
    tick_counter = 0
    start_time = datetime(2026, 1, 1, 8, 0, 0)

    for t in range(total_ticks):
        for dev in fleet:
            dev_id = dev["device_id"]
            in_campaign = attack_start[dev_id] <= t < attack_start[dev_id] + CAMPAIGN_LEN
            pool = attack_pool if in_campaign else normal_pool
            sampled = pool.iloc[rng.integers(0, len(pool))]

            rows.append({
                **sampled.to_dict(),
                "device_id": dev_id,
                "device_archetype": dev["archetype"],
                "device_criticality": dev["criticality"],
                "scripted_campaign_active": in_campaign,
                "tick": tick_counter,
                "timestamp": (start_time + timedelta(seconds=tick_counter * 2)).isoformat(),
            })
            tick_counter += 1

    return pd.DataFrame(rows)


def main():
    os.makedirs(OUTPUTS_DIR, exist_ok=True)

    print("[1/4] Loading test traffic and trained artifacts...")
    test_df = assign_devices(load_raw_data(os.path.join(DATA_DIR, "NSL_KDD_Test.csv")), seed=SEED)
    pipeline = joblib.load(os.path.join(MODELS_DIR, "feature_pipeline.joblib"))
    engine = IntrusionDetectionEngine.load(os.path.join(MODELS_DIR, "ids_engine.joblib"))

    print("[2/4] Scoring all events with the intrusion detection engine...")
    X_test = pipeline.transform(test_df)
    scores = engine.score(X_test)
    test_df = test_df.reset_index(drop=True)
    test_df["attack_probability"] = scores["attack_probability"]
    test_df["anomaly_score"] = scores["anomaly_score"]
    test_df["predicted_label"] = scores["predicted_label"]

    print("[3/4] Building scripted scenario timeline and running trust + policy engines...")
    ordered = build_scenario_timeline(test_df)

    trust_engine = TrustEngine()
    policy_engine = AdaptivePolicyEngine()

    log_rows = []
    first_quarantine_event = {}    # device's own Nth event, not the shared global tick
    first_malicious_event = {}
    device_event_count = {}

    for _, row in ordered.iterrows():
        dev = row["device_id"]
        device_event_count[dev] = device_event_count.get(dev, 0) + 1
        local_seq = device_event_count[dev]

        result = trust_engine.update(
            device_id=dev, archetype=row["device_archetype"], criticality=row["device_criticality"],
            attack_probability=float(row["attack_probability"]), anomaly_score=float(row["anomaly_score"]),
        )
        decision = policy_engine.decide(
            device_id=dev, trust_score=result["trust_score"], criticality=row["device_criticality"],
            global_threat_level=result["global_threat_level"], archetype=row["device_archetype"],
        )

        if row["is_attack"] == 1 and dev not in first_malicious_event:
            first_malicious_event[dev] = local_seq
        if decision["action"] == "QUARANTINE" and dev not in first_quarantine_event:
            first_quarantine_event[dev] = local_seq

        log_rows.append({
            "tick": int(row["tick"]),
            "timestamp": row["timestamp"],
            "device_id": dev,
            "archetype": row["device_archetype"],
            "criticality": row["device_criticality"],
            "scripted_campaign_active": bool(row["scripted_campaign_active"]),
            "true_is_attack": int(row["is_attack"]),
            "true_attack_category": row["attack_category"],
            "predicted_label": int(row["predicted_label"]),
            "attack_probability": round(float(row["attack_probability"]), 4),
            "anomaly_score": round(float(row["anomaly_score"]), 4),
            "trust_score": round(result["trust_score"], 2),
            "global_threat_level": round(result["global_threat_level"], 4),
            "policy_action": decision["action"],
            "reason": decision["reason"],
        })

    log_df = pd.DataFrame(log_rows)
    log_path = os.path.join(OUTPUTS_DIR, "simulation_log.csv")
    log_df.to_csv(log_path, index=False)

    print("[4/4] Computing summary metrics...")
    response_latencies = []
    for dev, mal_seq in first_malicious_event.items():
        if dev in first_quarantine_event and first_quarantine_event[dev] >= mal_seq:
            response_latencies.append(first_quarantine_event[dev] - mal_seq)

    action_counts = log_df["policy_action"].value_counts().to_dict()
    benign_over_blocked = log_df[(log_df["true_is_attack"] == 0) &
                                  (log_df["policy_action"].isin(["RESTRICT", "QUARANTINE"]))]
    benign_total = (log_df["true_is_attack"] == 0).sum()

    summary = {
        "total_events": int(len(log_df)),
        "devices_simulated": int(log_df["device_id"].nunique()),
        "devices_ever_quarantined": len(first_quarantine_event),
        "policy_action_counts": action_counts,
        "avg_trust_score_final": {
            dev: round(g["trust_score"].iloc[-1], 2)
            for dev, g in log_df.groupby("device_id")
        },
        "mean_own_events_to_quarantine_after_first_attack": (
            round(sum(response_latencies) / len(response_latencies), 2) if response_latencies else None
        ),
        "benign_traffic_over_restricted_rate": round(len(benign_over_blocked) / benign_total, 4) if benign_total else None,
        "final_global_threat_level": round(trust_engine.global_threat_level, 4),
    }

    with open(os.path.join(OUTPUTS_DIR, "simulation_summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nSimulation complete: {summary['total_events']} events across "
          f"{summary['devices_simulated']} devices.")
    print(f"Devices quarantined at least once: {summary['devices_ever_quarantined']}")
    print(f"Mean of device's own malicious events seen before quarantine: {summary['mean_own_events_to_quarantine_after_first_attack']}")
    print(f"Over-restriction rate on benign traffic: {summary['benign_traffic_over_restricted_rate']}")
    print(f"\nLog written to {log_path}")
    print("Next: run `streamlit run dashboard/app.py` to view results.")


if __name__ == "__main__":
    main()
