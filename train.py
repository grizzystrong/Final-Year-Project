"""
train.py
--------
Entry point: loads data, trains the intrusion detection engine (supervised
+ unsupervised), evaluates it on the held-out test split, and persists the
trained model + feature pipeline to models/ for simulate.py and the
dashboard to reuse.

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

    print("[1/4] Loading and preparing data (NSL-KDD + simulated IoT device layer)...")
    data = load_and_prepare(
        os.path.join(DATA_DIR, "NSL_KDD_Train.csv"),
        os.path.join(DATA_DIR, "NSL_KDD_Test.csv"),
    )
    print(f"      train={data['X_train'].shape}, test={data['X_test'].shape}, "
          f"attack rate train={data['y_train'].mean():.3f} test={data['y_test'].mean():.3f}")

    print("[2/4] Training intrusion detection engine (RandomForest + IsolationForest)...")
    engine = IntrusionDetectionEngine()
    engine.fit(data["X_train"], data["y_train"])

    print("[3/4] Evaluating on held-out test set...")
    eval_result = engine.evaluate(data["X_test"], data["y_test"])
    acc = eval_result["classification_report"]["accuracy"]
    print(f"      Accuracy={acc:.4f}  ROC-AUC={eval_result['roc_auc']:.4f}")
    print(f"      Confusion matrix: {eval_result['confusion_matrix']}")

    print("[4/4] Saving model + pipeline + evaluation report...")
    engine.save(os.path.join(MODELS_DIR, "ids_engine.joblib"))
    joblib.dump(data["pipeline"], os.path.join(MODELS_DIR, "feature_pipeline.joblib"))
    with open(os.path.join(OUTPUTS_DIR, "model_eval.json"), "w") as f:
        json.dump(eval_result, f, indent=2)

    print("\nDone. Artifacts written to models/ and outputs/model_eval.json")
    print("Next: run `python simulate.py` to run the adaptive zero-trust simulation.")


if __name__ == "__main__":
    main()
