"""
ids_model.py (v2)
-------------------
Upgrades from v1:
- Compares two strong supervised learners (RandomForest, HistGradientBoosting)
  and combines them in a soft-voting ensemble -- the ensemble is what actually
  drives the trust engine, but all three are evaluated and reported, which
  gives a genuine "model comparison" result for the report.
- IsolationForest anomaly detector keeps the percentile-based calibration
  (raw IsolationForest.decision_function is centered near 0 with a tiny,
  data-dependent range -- a fixed rescaling formula silently miscalibrates
  it, so bounds are calibrated against the real training-normal distribution).
- Exposes feature importances for the dashboard's explainability panel.
"""

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score


class IntrusionDetectionEngine:
    def __init__(self, random_state: int = 42):
        self.random_state = random_state
        self.rf = RandomForestClassifier(
            n_estimators=150, max_depth=20, n_jobs=-1,
            random_state=random_state, class_weight="balanced",
        )
        self.hgb = HistGradientBoostingClassifier(
            max_iter=150, max_depth=12, random_state=random_state,
        )
        self.anomaly_detector = IsolationForest(
            n_estimators=120, contamination=0.05, random_state=random_state, n_jobs=-1,
        )
        self._anomaly_low = None
        self._anomaly_high = None
        self.feature_names = None

    def fit(self, X_train: np.ndarray, y_train: np.ndarray, feature_names=None):
        self.feature_names = feature_names
        self.rf.fit(X_train, y_train)
        self.hgb.fit(X_train, y_train)

        normal_mask = y_train == 0
        self.anomaly_detector.fit(X_train[normal_mask])
        raw_normal = self.anomaly_detector.decision_function(X_train[normal_mask])
        self._anomaly_low = float(np.percentile(raw_normal, 1))
        self._anomaly_high = float(np.percentile(raw_normal, 99))
        return self

    def _ensemble_proba(self, X: np.ndarray) -> np.ndarray:
        # Soft vote: average the two learners' probability estimates.
        p_rf = self.rf.predict_proba(X)[:, 1]
        p_hgb = self.hgb.predict_proba(X)[:, 1]
        return (p_rf + p_hgb) / 2.0

    def score(self, X: np.ndarray) -> dict:
        attack_proba = self._ensemble_proba(X)
        predicted_label = (attack_proba >= 0.5).astype(int)

        raw_anomaly = self.anomaly_detector.decision_function(X)
        span = max(self._anomaly_high - self._anomaly_low, 1e-9)
        normalized = (raw_anomaly - self._anomaly_low) / span
        anomaly_score = 1.0 - np.clip(normalized, 0.0, 1.0)

        return {
            "attack_probability": attack_proba,
            "predicted_label": predicted_label,
            "anomaly_score": anomaly_score,
        }

    def evaluate_all(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        """Per-model comparison (RF alone, HGB alone, ensemble) -- the
        'model comparison' table for the report."""
        results = {}
        for name, proba in [
            ("random_forest", self.rf.predict_proba(X_test)[:, 1]),
            ("hist_gradient_boosting", self.hgb.predict_proba(X_test)[:, 1]),
            ("ensemble", self._ensemble_proba(X_test)),
        ]:
            pred = (proba >= 0.5).astype(int)
            report = classification_report(y_test, pred, output_dict=True, zero_division=0)
            results[name] = {
                "accuracy": report["accuracy"],
                "precision": report.get("1", {}).get("precision", 0),
                "recall": report.get("1", {}).get("recall", 0),
                "f1": report.get("1", {}).get("f1-score", 0),
                "roc_auc": roc_auc_score(y_test, proba),
            }

        ensemble_result = self.score(X_test)
        cm = confusion_matrix(y_test, ensemble_result["predicted_label"]).tolist()
        report = classification_report(y_test, ensemble_result["predicted_label"], output_dict=True, zero_division=0)

        return {
            "model_comparison": results,
            "classification_report": report,
            "confusion_matrix": cm,
            "roc_auc": results["ensemble"]["roc_auc"],
        }

    def feature_importances(self, top_n: int = 15) -> list:
        if self.feature_names is None:
            return []
        importances = self.rf.feature_importances_
        order = np.argsort(importances)[::-1][:top_n]
        return [{"feature": self.feature_names[i], "importance": round(float(importances[i]), 4)} for i in order]

    def save(self, path: str):
        joblib.dump({
            "rf": self.rf, "hgb": self.hgb, "anomaly_detector": self.anomaly_detector,
            "anomaly_low": self._anomaly_low, "anomaly_high": self._anomaly_high,
            "feature_names": self.feature_names,
        }, path)

    @classmethod
    def load(cls, path: str):
        obj = joblib.load(path)
        engine = cls()
        engine.rf = obj["rf"]
        engine.hgb = obj["hgb"]
        engine.anomaly_detector = obj["anomaly_detector"]
        engine._anomaly_low = obj["anomaly_low"]
        engine._anomaly_high = obj["anomaly_high"]
        engine.feature_names = obj["feature_names"]
        return engine
