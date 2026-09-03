"""
preprocessing.py
-----------------
Loads the NSL-KDD network intrusion dataset, maps raw attack labels to
attack categories, layers a simulated IoT-device identity model on top of
each traffic record, and prepares numeric feature matrices for the
intrusion detection model.

NOTE ON DATA: NSL-KDD is a general network-intrusion benchmark, not a
native IoT packet capture. Real IoT-native datasets (N-BaIoT, TON_IoT,
CICIoT2023) are hosted behind UCI/Kaggle and are not fetchable from this
environment. To keep the prototype's detection logic grounded in real,
labeled attack traffic, each NSL-KDD connection record is deterministically
assigned to a simulated IoT device profile below. Swap in a real IoT
dataset by replacing `load_raw_data()` and `assign_devices()` — the rest
of the pipeline (model, trust engine, policy engine) is dataset-agnostic.
"""

import hashlib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder

COLUMN_NAMES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label",
]

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

ATTACK_CATEGORY_MAP = {
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS", "smurf": "DoS",
    "teardrop": "DoS", "apache2": "DoS", "udpstorm": "DoS", "processtable": "DoS",
    "mailbomb": "DoS", "worm": "DoS",
    "satan": "Probe", "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "mscan": "Probe", "saint": "Probe",
    "guess_passwd": "R2L", "ftp_write": "R2L", "imap": "R2L", "phf": "R2L",
    "multihop": "R2L", "warezmaster": "R2L", "warezclient": "R2L", "spy": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "snmpguess": "R2L", "snmpgetattack": "R2L",
    "httptunnel": "R2L", "sendmail": "R2L", "named": "R2L",
    "buffer_overflow": "U2R", "loadmodule": "U2R", "rootkit": "U2R", "perl": "U2R",
    "sqlattack": "U2R", "xterm": "U2R", "ps": "U2R",
    "normal": "Normal",
}

# Simulated IoT device fleet. Each device has an archetype (used for
# criticality weighting in the trust/policy engines) and is deterministically
# fed a slice of traffic based on its (protocol, service) traffic footprint,
# so a given device sees behaviorally-consistent traffic across the
# simulation -- which is what makes a per-device trust *baseline* meaningful.
DEVICE_FLEET = [
    {"device_id": "cam-01", "archetype": "smart_camera", "criticality": 0.6},
    {"device_id": "cam-02", "archetype": "smart_camera", "criticality": 0.6},
    {"device_id": "doorbell-01", "archetype": "smart_doorbell", "criticality": 0.7},
    {"device_id": "thermostat-01", "archetype": "smart_thermostat", "criticality": 0.4},
    {"device_id": "lock-01", "archetype": "smart_lock", "criticality": 0.9},
    {"device_id": "babymonitor-01", "archetype": "baby_monitor", "criticality": 0.8},
    {"device_id": "plug-01", "archetype": "smart_plug", "criticality": 0.3},
    {"device_id": "plug-02", "archetype": "smart_plug", "criticality": 0.3},
    {"device_id": "speaker-01", "archetype": "smart_speaker", "criticality": 0.5},
    {"device_id": "hub-01", "archetype": "gateway_hub", "criticality": 1.0},
    {"device_id": "tv-01", "archetype": "smart_tv", "criticality": 0.4},
    {"device_id": "sensor-01", "archetype": "motion_sensor", "criticality": 0.5},
]


def load_raw_data(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, names=COLUMN_NAMES)
    df["attack_category"] = df["label"].map(ATTACK_CATEGORY_MAP).fillna("Unknown_Attack")
    df["is_attack"] = (df["attack_category"] != "Normal").astype(int)
    return df


def assign_devices(df: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    """Deterministically map each record to a simulated IoT device based on
    its (protocol_type, service) traffic signature, so each device exhibits
    a behaviorally-consistent pattern over the course of the simulation."""
    df = df.copy()
    combo_key = (df["protocol_type"].astype(str) + "|" + df["service"].astype(str))

    def pick_device(key: str) -> int:
        h = int(hashlib.sha256(f"{seed}-{key}".encode()).hexdigest(), 16)
        return h % len(DEVICE_FLEET)

    idx = combo_key.map(pick_device)
    df["device_id"] = idx.map(lambda i: DEVICE_FLEET[i]["device_id"])
    df["device_archetype"] = idx.map(lambda i: DEVICE_FLEET[i]["archetype"])
    df["device_criticality"] = idx.map(lambda i: DEVICE_FLEET[i]["criticality"])
    return df


class FeaturePipeline:
    """Fits encoders/scaler on training data, applies consistently to any split."""

    def __init__(self):
        self.encoders = {c: LabelEncoder() for c in CATEGORICAL_COLS}
        self.scaler = StandardScaler()
        self.feature_cols = None

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        work = df.copy()
        for c in CATEGORICAL_COLS:
            work[c] = self.encoders[c].fit_transform(work[c].astype(str))
        self.feature_cols = [c for c in COLUMN_NAMES if c != "label"]
        X = work[self.feature_cols].astype(float).values
        return self.scaler.fit_transform(X)

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        work = df.copy()
        for c in CATEGORICAL_COLS:
            known = set(self.encoders[c].classes_)
            work[c] = work[c].astype(str).apply(lambda v: v if v in known else self.encoders[c].classes_[0])
            work[c] = self.encoders[c].transform(work[c])
        X = work[self.feature_cols].astype(float).values
        return self.scaler.transform(X)


def load_and_prepare(train_path: str, test_path: str, seed: int = 42):
    train_df = assign_devices(load_raw_data(train_path), seed=seed)
    test_df = assign_devices(load_raw_data(test_path), seed=seed)

    pipeline = FeaturePipeline()
    X_train = pipeline.fit_transform(train_df)
    X_test = pipeline.transform(test_df)

    y_train = train_df["is_attack"].values
    y_test = test_df["is_attack"].values

    return {
        "train_df": train_df, "test_df": test_df,
        "X_train": X_train, "X_test": X_test,
        "y_train": y_train, "y_test": y_test,
        "pipeline": pipeline,
    }


if __name__ == "__main__":
    data = load_and_prepare("data/NSL_KDD_Train.csv", "data/NSL_KDD_Test.csv")
    print("Train shape:", data["X_train"].shape, "Test shape:", data["X_test"].shape)
    print("Attack rate (train):", data["y_train"].mean().round(3))
    print(data["train_df"]["device_id"].value_counts())
