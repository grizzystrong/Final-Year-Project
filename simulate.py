"""
simulate.py (v3) -- replays held-out traffic through scripted per-device attack
scenarios using the four-factor trust engine and the adaptive policy engine, then
exports results for the website (docs/data.js) and the Streamlit dashboard (outputs/).

Environment note: the step-up challenge outcome is part of the *simulated
environment* (legitimate devices usually pass, attackers usually fail); the
detector/trust engine never sees ground-truth labels.
"""
import json, os, sys
from datetime import datetime, timedelta
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import joblib, numpy as np, pandas as pd
from src.preprocessing import load_raw_data, assign_devices, add_synthetic_iot_telemetry, DEVICE_FLEET, DEVICE_BY_ID
from src.ids_model import IntrusionDetectionEngine
from src.trust_engine import TrustEngine, WEIGHTS
from src.policy_engine import AdaptivePolicyEngine

SEED, STAGGER, LEAD, CAMPAIGN, TAIL = 42, 40, 100, 25, 80
MINUTES_PER_ROUND = 4
ACTIONS = ["ALLOW", "STEP_UP_VERIFICATION", "RESTRICT", "QUARANTINE"]
START = datetime(2026, 1, 1, 5, 0, 0)


def build_timeline(test_df, rng):
    normal, attack = test_df[test_df.is_attack == 0].reset_index(drop=True), test_df[test_df.is_attack == 1].reset_index(drop=True)
    total = LEAD + (len(DEVICE_FLEET) - 1) * STAGGER + CAMPAIGN + TAIL
    start = {d["device_id"]: LEAD + i * STAGGER for i, d in enumerate(DEVICE_FLEET)}
    rows = []
    for t in range(total):
        for i, d in enumerate(DEVICE_FLEET):
            live = start[d["device_id"]] <= t < start[d["device_id"]] + CAMPAIGN
            pool = attack if live else normal
            r = pool.iloc[rng.integers(0, len(pool))].to_dict()
            src = DEVICE_BY_ID[r["device_id"]]  # re-home the telemetry onto the host device's own profile
            r["requests_per_min"] = round(r["requests_per_min"] / src["rpm_base"] * d["rpm_base"], 2)
            r["avg_payload_bytes"] = round(r["avg_payload_bytes"] / src["payload_base"] * d["payload_base"], 1)
            r.update(device_id=d["device_id"], round=t, campaign=live,
                     timestamp=START + timedelta(minutes=t * MINUTES_PER_ROUND, seconds=10 * i))
            rows.append(r)
    return pd.DataFrame(rows), total, start



def export_events(test_df, rng):
    """Replay pool for the per-user website: scored events (model outputs), telemetry as ratios to the host profile."""
    svc = sorted(test_df["service"].unique().tolist()); cats = ["Normal", "DoS", "Probe", "R2L", "U2R"]
    def rows(df):
        out = []
        for _, r in df.iterrows():
            b = DEVICE_BY_ID[r["device_id"]]
            out.append([round(float(r["attack_probability"]), 3), round(float(r["anomaly_score"]), 3),
                        round(float(r["requests_per_min"]) / b["rpm_base"], 2), round(float(r["avg_payload_bytes"]) / b["payload_base"], 2),
                        int(min(r["num_failed_logins"], 3)), int(r["is_guest_login"]), int(r["su_attempted"] > 0 or r["root_shell"] > 0),
                        svc.index(r["service"]), cats.index(r["attack_category"]) if r["attack_category"] in cats else 1])
        return out
    n = test_df[test_df.is_attack == 0].sample(1500, random_state=SEED); a = test_df[test_df.is_attack == 1].sample(1500, random_state=SEED)
    open("docs/events.js", "w").write("window.ZT_EVENTS=" + json.dumps({"services": svc, "cats": cats, "normal": rows(n), "attack": rows(a)}, separators=(",", ":")) + ";")

def main():
    os.makedirs("outputs", exist_ok=True); os.makedirs("docs", exist_ok=True)
    rng = np.random.default_rng(SEED)
    test_df = add_synthetic_iot_telemetry(assign_devices(load_raw_data("data/NSL_KDD_Test.csv"), SEED), SEED + 1).reset_index(drop=True)
    pipe, engine = joblib.load("models/feature_pipeline.joblib"), IntrusionDetectionEngine.load("models/ids_engine.joblib")
    sc = engine.score(pipe.transform(test_df))
    test_df["attack_probability"], test_df["anomaly_score"], test_df["predicted_label"] = sc["attack_probability"], sc["anomaly_score"], sc["predicted_label"]
    export_events(test_df, rng)
    timeline, total, start = build_timeline(test_df, rng)

    te, pe = TrustEngine(), AdaptivePolicyEngine()
    meta = {d["device_id"]: d for d in DEVICE_FLEET}
    for d in DEVICE_FLEET: te.register(d)
    pending, last_chal, seq, first_mal, first_q, chal_stats = {}, {}, {}, {}, {}, {"issued": 0, "passed": 0}
    out = []
    for _, r in timeline.iterrows():
        dev = r["device_id"]; m = meta[dev]; seq[dev] = seq.get(dev, 0) + 1
        if dev in pending:  # apply the previous step-up challenge result
            te.apply_challenge(dev, pending.pop(dev))
        res = te.update(dev, r, r["timestamp"].hour, m["exposure"], m["payload_base"])
        dec = pe.decide(dev, res["trust_score"], m["criticality"], res["global_threat_level"], m["archetype"])
        chal = ""
        if dec["action"] in ("STEP_UP_VERIFICATION", "RESTRICT") and m["mfa_capable"] and seq[dev] - last_chal.get(dev, -99) >= 6:
            ok = rng.random() < (0.97 if r["is_attack"] == 0 else 0.25)
            pending[dev], last_chal[dev], chal = ok, seq[dev], "pass" if ok else "fail"
            chal_stats["issued"] += 1; chal_stats["passed"] += int(ok)
        if r["is_attack"] and dev not in first_mal: first_mal[dev] = seq[dev]
        if dec["action"] == "QUARANTINE" and dev not in first_q: first_q[dev] = seq[dev]
        out.append({"tick": len(out), "round": int(r["round"]), "timestamp": r["timestamp"].isoformat(), "device_id": dev,
                    "archetype": m["archetype"], "criticality": m["criticality"], "scripted_campaign_active": bool(r["campaign"]),
                    "true_is_attack": int(r["is_attack"]), "true_attack_category": r["attack_category"],
                    "predicted_label": int(r["predicted_label"]), "attack_probability": round(float(r["attack_probability"]), 4),
                    "anomaly_score": round(float(r["anomaly_score"]), 4), "requests_per_min": r["requests_per_min"],
                    "avg_payload_bytes": r["avg_payload_bytes"], "identity_confidence": round(res["identity"], 4),
                    "behavior_score": round(res["behavior"], 4), "historical_reputation": round(res["reputation"], 4),
                    "contextual_risk": round(res["context_risk"], 4), "challenge": chal,
                    "trust_score": round(res["trust_score"], 2), "global_threat_level": round(res["global_threat_level"], 4),
                    "policy_action": dec["action"], "reason": dec["reason"]})
    log = pd.DataFrame(out); log.to_csv("outputs/simulation_log.csv", index=False)

    lat = [first_q[d] - first_mal[d] for d in first_mal if d in first_q and first_q[d] >= first_mal[d]]
    ben = log[log.true_is_attack == 0]
    summary = {"total_events": len(log), "devices_simulated": log.device_id.nunique(), "devices_ever_quarantined": len(first_q),
               "policy_action_counts": log.policy_action.value_counts().to_dict(),
               "avg_trust_score_final": {d: round(g.trust_score.iloc[-1], 2) for d, g in log.groupby("device_id")},
               "mean_own_events_to_quarantine_after_first_attack": round(sum(lat) / len(lat), 2) if lat else None,
               "benign_traffic_over_restricted_rate": round(ben.policy_action.isin(["RESTRICT", "QUARANTINE"]).mean(), 4),
               "final_global_threat_level": round(te.threat, 4), "step_up_challenges": chal_stats,
               "trust_factor_weights": WEIGHTS}
    json.dump(summary, open("outputs/simulation_summary.json", "w"), indent=2)

    # ---- website data (docs/data.js)
    ev = json.load(open("outputs/model_eval.json"))
    rounds = sorted(log["round"].unique()); times = [log[log["round"] == t].timestamp.iloc[0][:16] for t in rounds]
    devs = []
    for d in DEVICE_FLEET:
        g = log[log.device_id == d["device_id"]].sort_values("round")
        devs.append({"id": d["device_id"], "type": d["archetype"], "criticality": d["criticality"], "exposure": d["exposure"],
                     "mfa": d["mfa_capable"], "certAge": d["cert_age_days"],
                     "campaign": [int(g[g.scripted_campaign_active]["round"].min()), int(g[g.scripted_campaign_active]["round"].max())],
                     "cats": sorted(g[g.scripted_campaign_active].true_attack_category.unique().tolist()),
                     "trust": g.trust_score.round(1).tolist(), "identity": g.identity_confidence.round(2).tolist(),
                     "behavior": g.behavior_score.round(2).tolist(), "reputation": g.historical_reputation.round(2).tolist(),
                     "context": (1 - g.contextual_risk).round(2).tolist(), "action": [ACTIONS.index(a) for a in g.policy_action],
                     "challenge": g.challenge.tolist()})
    data = {"times": times, "devices": devs, "summary": summary, "weights": WEIGHTS, "model": ev["model_comparison"],
            "importances": ev["feature_importances"][:8], "confusion": ev["confusion_matrix"]}
    open("docs/data.js", "w").write("window.ZT_DATA=" + json.dumps(data, separators=(",", ":")) + ";")
    print(json.dumps({k: summary[k] for k in ["devices_ever_quarantined", "mean_own_events_to_quarantine_after_first_attack",
          "benign_traffic_over_restricted_rate", "policy_action_counts", "step_up_challenges"]}))
    print(summary["avg_trust_score_final"])

if __name__ == "__main__":
    main()
