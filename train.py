"""
train.py (v2)
-------------
Trains the ensemble intrusion detection engine, evaluates RF/HGB/ensemble
individually, and persists everything needed by simulate.py and the
dashboard.

Usage:
    python train.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import joblib
from src.preprocessing import load_and_prepare
from src.ids_model import IntrusionDetectionEngine

DATA_DIR = "data"
MODELS_DIR = "models"
OUTPUTS_DIR = "outputs"


def main():
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(OUTPUTS_DIR, exist_ok=True)

    print("[1/4] Loading data + synthetic IoT telemetry features...")
    data = load_and_prepare(
        os.path.join(DATA_DIR, "NSL_KDD_Train.csv"),
        os.path.join(DATA_DIR, "NSL_KDD_Test.csv"),
    )
    print(f"      train={data['X_train'].shape}, test={data['X_test'].shape}")

    print("[2/4] Training RandomForest + HistGradientBoosting ensemble + IsolationForest...")
    engine = IntrusionDetectionEngine()
    engine.fit(data["X_train"], data["y_train"], feature_names=data["pipeline"].feature_cols)

    print("[3/4] Evaluating all models on held-out test set...")
    eval_result = engine.evaluate_all(data["X_test"], data["y_test"])
    for name, m in eval_result["model_comparison"].items():
        print(f"      {name:24s} acc={m['accuracy']:.4f} f1={m['f1']:.4f} auc={m['roc_auc']:.4f}")

    importances = engine.feature_importances()

    print("[4/4] Saving model + pipeline + evaluation report...")
    engine.save(os.path.join(MODELS_DIR, "ids_engine.joblib"))
    joblib.dump(data["pipeline"], os.path.join(MODELS_DIR, "feature_pipeline.joblib"))
    with open(os.path.join(OUTPUTS_DIR, "model_eval.json"), "w") as f:
        json.dump({**eval_result, "feature_importances": importances}, f, indent=2)

    print("\nDone. Next: run `python simulate.py`.")


if __name__ == "__main__":
    main()
