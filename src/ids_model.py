"""
ids_model.py
------------
The "intelligent" detection core. Combines two complementary signals, the
way a real production IDS/IPS typically would:

1. A supervised RandomForestClassifier trained on labeled traffic ->
   calibrated probability that a given connection is malicious.
2. An unsupervised IsolationForest trained only on *normal* traffic ->
   an anomaly score that can flag novel/unseen attack patterns the
   supervised model was never trained on (NSL-KDD's test set deliberately
   contains attack types absent from the training set, which is exactly
   the "unknown threat" scenario zero-trust continuous verification is
   meant to catch).

Both signals are fed into the TrustEngine, not just a single hard label --
this is what lets the trust score reflect *degrees* of suspicion instead
of a brittle binary allow/block call.
"""

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score


class IntrusionDetectionEngine:
    def __init__(self, n_estimators: int = 200, random_state: int = 42):
        self.classifier = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=20,
            n_jobs=-1,
            random_state=random_state,
            class_weight="balanced",
        )
        self.anomaly_detector = IsolationForest(
            n_estimators=150,
            contamination=0.05,
            random_state=random_state,
            n_jobs=-1,
        )

    def fit(self, X_train: np.ndarray, y_train: np.ndarray):
        self.classifier.fit(X_train, y_train)
        # Anomaly detector only ever sees benign traffic during fitting, so it
        # learns a boundary of "normal" and flags deviation from it --
        # independent of whether that deviation matches a known attack label.
        normal_mask = y_train == 0
        self.anomaly_detector.fit(X_train[normal_mask])

        # decision_function is centered near 0 with a small, data-dependent
        # range (NOT 0..1 or -1..1), so a fixed rescaling formula silently
        # miscalibrates the score. Instead, calibrate against the actual
        # distribution of raw scores on known-normal training data: the
        # 1st/99th percentiles define "typical inlier" bounds, and anything
        # at or beyond them maps to anomaly_score 0 / 1 respectively.
        raw_normal = self.anomaly_detector.decision_function(X_train[normal_mask])
        self._anomaly_low = float(np.percentile(raw_normal, 1))
        self._anomaly_high = float(np.percentile(raw_normal, 99))
        return self

    def score(self, X: np.ndarray) -> dict:
        attack_proba = self.classifier.predict_proba(X)[:, 1]
        predicted_label = self.classifier.predict(X)
        raw_anomaly = self.anomaly_detector.decision_function(X)  # higher = more normal
        span = max(self._anomaly_high - self._anomaly_low, 1e-9)
        normalized = (raw_anomaly - self._anomaly_low) / span
        anomaly_score = 1.0 - np.clip(normalized, 0.0, 1.0)  # 0..1, higher = more anomalous
        return {
            "attack_probability": attack_proba,
            "predicted_label": predicted_label,
            "anomaly_score": anomaly_score,
        }

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        result = self.score(X_test)
        report = classification_report(y_test, result["predicted_label"], output_dict=True, zero_division=0)
        cm = confusion_matrix(y_test, result["predicted_label"]).tolist()
        auc = roc_auc_score(y_test, result["attack_probability"])
        return {"classification_report": report, "confusion_matrix": cm, "roc_auc": auc}

    def save(self, path: str):
        joblib.dump({
            "classifier": self.classifier,
            "anomaly_detector": self.anomaly_detector,
            "anomaly_low": self._anomaly_low,
            "anomaly_high": self._anomaly_high,
        }, path)

    @classmethod
    def load(cls, path: str):
        obj = joblib.load(path)
        engine = cls()
        engine.classifier = obj["classifier"]
        engine.anomaly_detector = obj["anomaly_detector"]
        engine._anomaly_low = obj["anomaly_low"]
        engine._anomaly_high = obj["anomaly_high"]
        return engine
