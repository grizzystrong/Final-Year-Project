"""
policy_engine.py
-----------------
Turns a device's trust score into an actual intrusion-*prevention* action
(not just a detection alert). Implements least-privilege, adaptive
micro-segmentation: the same trust score can lead to a different action
depending on how critical the device is and how elevated the current
network-wide threat level is (the thresholds themselves move).

Actions, from least to most restrictive:
- ALLOW               : normal least-privilege access
- STEP_UP_VERIFICATION: extra logging + continued close monitoring
- RESTRICT            : micro-segmented to minimum-required services only
- QUARANTINE          : isolated from the network entirely

Every decision returns a human-readable reason and the effective
thresholds used at that moment, because Zero Trust mandates continuous,
auditable logging of *why* an access decision was made -- not just what
the decision was.
"""

from dataclasses import dataclass


@dataclass
class PolicyThresholds:
    allow: float = 80.0
    step_up: float = 55.0
    restrict: float = 25.0
    # QUARANTINE is anything below `restrict`


class AdaptivePolicyEngine:
    def __init__(self, base_thresholds: PolicyThresholds = None):
        self.base = base_thresholds or PolicyThresholds()

    def _effective_thresholds(self, criticality: float, global_threat_level: float) -> PolicyThresholds:
        # More critical devices, and a hotter network-wide threat climate,
        # both raise the bar required to earn full access -- classic
        # least-privilege + adaptive re-tuning.
        bump = criticality * 8.0 + global_threat_level * 10.0
        return PolicyThresholds(
            allow=min(97.0, self.base.allow + bump),
            step_up=min(90.0, self.base.step_up + bump * 0.6),
            restrict=self.base.restrict,
        )

    def decide(self, device_id: str, trust_score: float, criticality: float,
               global_threat_level: float, archetype: str = "") -> dict:
        th = self._effective_thresholds(criticality, global_threat_level)

        if trust_score >= th.allow:
            action, reason = "ALLOW", (
                f"Trust {trust_score:.1f} meets adaptive allow threshold "
                f"{th.allow:.1f} for this device's criticality/network state."
            )
        elif trust_score >= th.step_up:
            action, reason = "STEP_UP_VERIFICATION", (
                f"Trust {trust_score:.1f} is below allow threshold {th.allow:.1f}; "
                f"device kept under closer monitoring rather than full access."
            )
        elif trust_score >= th.restrict:
            action, reason = "RESTRICT", (
                f"Trust {trust_score:.1f} below step-up threshold {th.step_up:.1f}; "
                f"device micro-segmented to minimum-required services."
            )
        else:
            action, reason = "QUARANTINE", (
                f"Trust {trust_score:.1f} below restrict threshold {th.restrict:.1f}; "
                f"device isolated from the network pending investigation."
            )

        return {
            "device_id": device_id,
            "action": action,
            "reason": reason,
            "trust_score": trust_score,
            "effective_allow_threshold": th.allow,
            "effective_step_up_threshold": th.step_up,
            "effective_restrict_threshold": th.restrict,
        }
