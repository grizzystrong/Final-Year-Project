"""
trust_engine.py
----------------
Implements continuous, adaptive trust scoring per device -- the core
"never trust, always verify" mechanic of Zero Trust Architecture.

Design principles encoded here (each maps to a standard ZTA tenet):

- No device is ever "permanently" trusted. Every event nudges the score.
- Trust is asymmetric: it falls fast on suspicious behavior and rebuilds
  slowly, because the cost of under-reacting to a real intrusion is far
  higher than the cost of a temporarily-cautious device.
- More critical devices (a smart lock vs. a smart plug) are held to a
  stricter standard -- the same suspicion signal costs a critical device
  more trust than a low-value one (supports least-privilege segmentation
  downstream in the policy engine).
- The engine also tracks a *global* network threat level (an adaptive
  EWMA of recent network-wide malicious activity). When many devices are
  acting up at once, the whole network becomes more suspicious of
  everyone -- this is the "Adaptive" half of the framework: the system's
  sensitivity re-tunes itself to the current threat climate instead of
  using static, hand-picked thresholds forever.
"""

from dataclasses import dataclass, field


@dataclass
class DeviceTrustState:
    device_id: str
    archetype: str
    criticality: float  # 0..1, higher = more sensitive device
    trust_score: float = 70.0  # neutral starting trust, not full trust
    consecutive_suspicious: int = 0
    total_events: int = 0


class TrustEngine:
    def __init__(
        self,
        initial_trust: float = 70.0,
        recovery_rate: float = 0.07,
        base_penalty_gain: float = 0.22,
        threat_ewma_alpha: float = 0.03,
    ):
        self.initial_trust = initial_trust
        self.recovery_rate = recovery_rate
        self.base_penalty_gain = base_penalty_gain
        self.threat_ewma_alpha = threat_ewma_alpha
        self.devices: dict[str, DeviceTrustState] = {}
        self.global_threat_level: float = 0.0  # 0..1, EWMA of network-wide suspicion

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
        attack_probability: float, anomaly_score: float,
    ) -> dict:
        state = self._get_state(device_id, archetype, criticality)

        # Adaptive blend: when the network is already under elevated threat,
        # weight the anomaly signal (novel/unknown behavior) more heavily --
        # in a heightened-alert climate, "merely unusual" is treated as more
        # suspicious than it would be in calm conditions.
        anomaly_weight = 0.35 + 0.35 * self.global_threat_level
        classifier_weight = 1.0 - anomaly_weight
        suspicion = classifier_weight * attack_probability + anomaly_weight * anomaly_score
        suspicion = max(0.0, min(1.0, suspicion))

        target_trust = 100.0 * (1.0 - suspicion)

        if target_trust < state.trust_score:
            # Trust falls fast; critical devices fall faster for the same signal.
            gain = self.base_penalty_gain * (1.0 + criticality)
            state.consecutive_suspicious += 1
        else:
            # Trust rebuilds slowly and only through sustained clean behavior.
            gain = self.recovery_rate
            state.consecutive_suspicious = 0

        gain = min(gain, 1.0)
        new_trust = state.trust_score + gain * (target_trust - state.trust_score)

        # Small network-wide "re-verify everyone" tax during heightened alert.
        new_trust -= self.global_threat_level * 1.5
        new_trust = max(0.0, min(100.0, new_trust))

        state.trust_score = new_trust
        state.total_events += 1
        self._update_global_threat(suspicion)

        return {
            "trust_score": state.trust_score,
            "suspicion": suspicion,
            "consecutive_suspicious": state.consecutive_suspicious,
            "global_threat_level": self.global_threat_level,
        }

    def snapshot(self) -> list[dict]:
        return [
            {
                "device_id": s.device_id, "archetype": s.archetype,
                "criticality": s.criticality, "trust_score": s.trust_score,
                "total_events": s.total_events,
            }
            for s in self.devices.values()
        ]
