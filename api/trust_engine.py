"""
trust_engine.py (v3) -- four-factor continuous trust scoring.

  1. Identity confidence    : is this device who it claims to be? (credential age,
                              auth-failure / privilege signals, traffic fingerprint
                              vs. its device type, step-up challenge results)
  2. Behavior / anomaly     : classifier probability + anomaly score + deviation from
                              the device's own learned request-rate baseline
  3. Historical reputation  : slow-moving record of past conduct and past incidents
  4. Contextual risk        : time of day, service/protocol risk, exposure, and the
                              network-wide threat level

Factors are fused with a weighted GEOMETRIC mean, so one failing dimension drags
trust down instead of being averaged away. Trust then moves asymmetrically
(falls fast, recovers slowly; critical devices fall faster).
"""
import math
from dataclasses import dataclass

SERVICE_RISK = {"telnet": 0.9, "ftp": 0.6, "ftp_data": 0.4, "pop_3": 0.5, "smtp": 0.35,
                "http": 0.2, "private": 0.55, "other": 0.5, "ecr_i": 0.6, "eco_i": 0.5,
                "domain_u": 0.1, "auth": 0.4}
WEIGHTS = {"identity": 0.18, "behavior": 0.47, "reputation": 0.17, "context": 0.18}


@dataclass
class DeviceState:
    device_id: str
    archetype: str
    criticality: float
    identity_prior: float
    trust: float = 80.0
    identity: float = 0.9
    reputation: float = 0.85
    incident_weight: float = 0.0
    in_incident: bool = False
    baseline_rpm: float = None
    susp: float = 0.0
    events: int = 0


class TrustEngine:
    def __init__(self, recovery_rate=0.09, penalty_gain=0.5, threat_alpha=0.03):
        self.recovery_rate, self.penalty_gain, self.threat_alpha = recovery_rate, penalty_gain, threat_alpha
        self.devices, self.threat = {}, 0.0

    def register(self, d: dict):
        prior = 1.0 - 0.15 * d["cert_age_days"] / 365.0 - (0.0 if d["mfa_capable"] else 0.05)
        self.devices[d["device_id"]] = DeviceState(d["device_id"], d["archetype"], d["criticality"], prior,
                                                   identity=prior)

    def apply_challenge(self, device_id: str, passed: bool):
        s = self.devices[device_id]
        s.identity = min(s.identity_prior, s.identity + 0.15) if passed else s.identity * 0.6

    def update(self, device_id, ev: dict, hour: int, exposure: str, payload_base: float) -> dict:
        s = self.devices[device_id]
        # ---- 2. behavior / anomaly
        aw = 0.30 + 0.25 * self.threat
        ml = (0.8 - aw) * ev["attack_probability"] + aw * ev["anomaly_score"]
        if s.baseline_rpm is None:
            s.baseline_rpm = ev["requests_per_min"]
        dev = min(1.0, abs(ev["requests_per_min"] - s.baseline_rpm) / (s.baseline_rpm + 5.0))
        raw = max(0.0, min(1.0, ml + 0.2 * dev))
        suspicion = 0.55 * raw + 0.45 * s.susp  # light smoothing: one noisy benign event must not crater trust
        s.susp = suspicion
        if ml < 0.3:  # only calm traffic may reshape "normal"
            s.baseline_rpm = 0.92 * s.baseline_rpm + 0.08 * ev["requests_per_min"]
        behavior = 1.0 - suspicion
        # ---- 1. identity confidence
        fingerprint = math.exp(-abs(math.log(max(ev["avg_payload_bytes"], 1) / payload_base)) / 1.5)
        auth_pen = min(0.6, 0.25 * min(ev["num_failed_logins"], 3) + 0.2 * ev["is_guest_login"]
                       + 0.3 * (ev["su_attempted"] > 0 or ev["root_shell"] > 0))
        id_target = s.identity_prior * fingerprint * (1.0 - auth_pen)
        s.identity = 0.7 * s.identity + 0.3 * id_target
        # ---- 3. historical reputation
        s.incident_weight *= 0.995
        s.reputation = 0.98 * s.reputation + 0.02 * behavior
        reputation = s.reputation * (0.88 ** s.incident_weight)
        # ---- 4. contextual risk
        time_risk = (0.5 if s.criticality >= 0.7 else 0.25) if 0 <= hour < 5 else 0.05
        svc = SERVICE_RISK.get(ev["service"], 0.3)
        expo = 0.3 if exposure == "internet" else 0.1
        context_risk = 0.35 * time_risk + 0.30 * svc + 0.15 * expo + 0.20 * self.threat
        # ---- fusion (weighted geometric mean, behavior weight rises with network threat)
        w = dict(WEIGHTS); w["behavior"] += 0.10 * self.threat
        z = sum(w.values())
        f = {"identity": s.identity, "behavior": behavior, "reputation": reputation, "context": 1.0 - context_risk}
        target = 100.0 * math.exp(sum(w[k] / z * math.log(max(f[k], 0.02)) for k in f))
        if target < s.trust:
            gain = min(self.penalty_gain * (1.0 + s.criticality), 1.0)
        else:
            gain = self.recovery_rate
        s.trust = max(0.0, min(100.0, s.trust + gain * (target - s.trust) - 1.5 * self.threat))
        if s.trust < 25 and not s.in_incident:
            s.in_incident, s.incident_weight = True, s.incident_weight + 1.0
        elif s.trust > 45:
            s.in_incident = False
        s.events += 1
        self.threat = (1 - self.threat_alpha) * self.threat + self.threat_alpha * suspicion
        return {"trust_score": s.trust, "identity": s.identity, "behavior": behavior,
                "reputation": reputation, "context_risk": context_risk, "suspicion": suspicion,
                "global_threat_level": self.threat}
