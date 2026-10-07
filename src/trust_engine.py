"""
trust_engine.py (v2)
----------------------
Continuous, adaptive per-device trust scoring. New in v2: a THIRD,
independent suspicion signal -- behavioral deviation from the device's own
learned baseline (a lightweight UEBA-style check), alongside the ML
classifier's attack probability and the anomaly detector's score. A device
tripping the classifier/anomaly detector is one thing; a device suddenly
behaving very differently from its *own* history is a distinct, additional
red flag, and real zero-trust systems use both.

Design principles (each maps to a standard ZTA tenet):
- No device is ever permanently trusted; every event nudges the score.
- Trust is asymmetric: falls fast, rebuilds slowly.
- More critical devices are held to a stricter standard.
- A device's own behavioral baseline is only updated during periods of low
  suspicion -- otherwise an ongoing attack could poison the device's
  definition of "normal" and mask itself as the new baseline.
- A network-wide adaptive threat level re-tunes sensitivity to the current
  climate instead of using static thresholds forever.
"""

from dataclasses import dataclass


@dataclass
class DeviceTrustState:
    device_id: str
    archetype: str
    criticality: float
    trust_score: float = 70.0
    consecutive_suspicious: int = 0
    total_events: int = 0
    baseline_rpm: float = None       # EWMA baseline of requests_per_min, only updated when calm
    baseline_initialized: bool = False


class TrustEngine:
    def __init__(
        self,
        initial_trust: float = 70.0,
        recovery_rate: float = 0.07,
        base_penalty_gain: float = 0.22,
        threat_ewma_alpha: float = 0.03,
        baseline_ewma_alpha: float = 0.08,
        calm_threshold: float = 0.3,
    ):
        self.initial_trust = initial_trust
        self.recovery_rate = recovery_rate
        self.base_penalty_gain = base_penalty_gain
        self.threat_ewma_alpha = threat_ewma_alpha
        self.baseline_ewma_alpha = baseline_ewma_alpha
        self.calm_threshold = calm_threshold
        self.devices: dict[str, DeviceTrustState] = {}
        self.global_threat_level: float = 0.0

    def _get_state(self, device_id: str, archetype: str, criticality: float) -> DeviceTrustState:
        if device_id not in self.devices:
            self.devices[device_id] = DeviceTrustState(
                device_id=device_id, archetype=archetype, criticality=criticality,
                trust_score=self.initial_trust,
            )
        return self.devices[device_id]

    def _update_global_threat(self, suspicion: float):
        a = self.threat_ewma_alpha
        self.global_threat_level = (1 - a) * self.global_threat_level + a * suspicion

    def update(
        self, device_id: str, archetype: str, criticality: float,
        attack_probability: float, anomaly_score: float, requests_per_min: float,
    ) -> dict:
        state = self._get_state(device_id, archetype, criticality)

        # --- ML-based suspicion (classifier + anomaly detector) ---
        anomaly_weight = 0.30 + 0.25 * self.global_threat_level
        classifier_weight = 1.0 - anomaly_weight - 0.20  # leave room for behavioral term
        ml_suspicion = classifier_weight * attack_probability + anomaly_weight * anomaly_score

        # --- Behavioral deviation from the device's OWN history ---
        if not state.baseline_initialized:
            state.baseline_rpm = requests_per_min
            state.baseline_initialized = True
        behavioral_deviation = abs(requests_per_min - state.baseline_rpm) / (state.baseline_rpm + 5.0)
        behavioral_deviation = min(1.0, behavioral_deviation)

        suspicion = ml_suspicion + 0.20 * behavioral_deviation
        suspicion = max(0.0, min(1.0, suspicion))

        # Only let calm traffic reshape what "normal" looks like for this device.
        if ml_suspicion < self.calm_threshold:
            a = self.baseline_ewma_alpha
            state.baseline_rpm = (1 - a) * state.baseline_rpm + a * requests_per_min

        target_trust = 100.0 * (1.0 - suspicion)

        if target_trust < state.trust_score:
            gain = min(self.base_penalty_gain * (1.0 + criticality), 1.0)
            state.consecutive_suspicious += 1
        else:
            gain = self.recovery_rate
            state.consecutive_suspicious = 0

        new_trust = state.trust_score + gain * (target_trust - state.trust_score)
        new_trust -= self.global_threat_level * 1.5
        new_trust = max(0.0, min(100.0, new_trust))

        state.trust_score = new_trust
        state.total_events += 1
        self._update_global_threat(suspicion)

        return {
            "trust_score": state.trust_score,
            "suspicion": suspicion,
            "ml_suspicion": ml_suspicion,
            "behavioral_deviation": behavioral_deviation,
            "consecutive_suspicious": state.consecutive_suspicious,
            "global_threat_level": self.global_threat_level,
        }

    def snapshot(self) -> list:
        return [
            {
                "device_id": s.device_id, "archetype": s.archetype,
                "criticality": s.criticality, "trust_score": s.trust_score,
                "total_events": s.total_events,
            }
            for s in self.devices.values()
        ]
