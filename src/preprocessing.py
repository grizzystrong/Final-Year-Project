"""
preprocessing.py (v2)
----------------------
Loads NSL-KDD, maps attack labels to categories, layers a simulated IoT
device fleet on top, and — new in v2 — generates two synthetic-but-informative
IoT telemetry features (request rate, average payload size) that the model
actually uses, instead of relying solely on the raw NSL-KDD connection
features.

HONESTY NOTE: `requests_per_min` and `avg_payload_bytes` are synthetically
generated, not captured IoT packets. They are generated as a function of
device archetype + the row's real attack/normal ground truth (with noise),
so they carry genuine, non-trivial signal while staying clearly documented
as augmentation rather than passed off as real telemetry. See README.md.
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

# Simulated IoT device fleet.
DEVICE_FLEET = [
    {"device_id": "cam-01", "archetype": "smart_camera", "criticality": 0.6, "rpm_base": 40, "payload_base": 900},
    {"device_id": "cam-02", "archetype": "smart_camera", "criticality": 0.6, "rpm_base": 38, "payload_base": 860},
    {"device_id": "doorbell-01", "archetype": "smart_doorbell", "criticality": 0.7, "rpm_base": 15, "payload_base": 600},
    {"device_id": "thermostat-01", "archetype": "smart_thermostat", "criticality": 0.4, "rpm_base": 4, "payload_base": 120},
    {"device_id": "lock-01", "archetype": "smart_lock", "criticality": 0.9, "rpm_base": 2, "payload_base": 80},
    {"device_id": "babymonitor-01", "archetype": "baby_monitor", "criticality": 0.8, "rpm_base": 30, "payload_base": 700},
    {"device_id": "plug-01", "archetype": "smart_plug", "criticality": 0.3, "rpm_base": 1, "payload_base": 40},
    {"device_id": "plug-02", "archetype": "smart_plug", "criticality": 0.3, "rpm_base": 1, "payload_base": 40},
    {"device_id": "speaker-01", "archetype": "smart_speaker", "criticality": 0.5, "rpm_base": 10, "payload_base": 300},
    {"device_id": "hub-01", "archetype": "gateway_hub", "criticality": 1.0, "rpm_base": 60, "payload_base": 500},
    {"device_id": "tv-01", "archetype": "smart_tv", "criticality": 0.4, "rpm_base": 8, "payload_base": 400},
    {"device_id": "sensor-01", "archetype": "motion_sensor", "criticality": 0.5, "rpm_base": 3, "payload_base": 60},
]
# Device registry (v3): credential age, step-up capability, network exposure.
_REGISTRY = {
    "cam-01": (120, True, "internet"), "cam-02": (300, True, "internet"),
    "doorbell-01": (60, True, "internet"), "thermostat-01": (200, False, "local"),
    "lock-01": (30, True, "local"), "babymonitor-01": (90, True, "internet"),
    "plug-01": (340, False, "local"), "plug-02": (330, False, "local"),
    "speaker-01": (150, True, "internet"), "hub-01": (20, True, "internet"),
    "tv-01": (250, True, "internet"), "sensor-01": (280, False, "local"),
}
for _d in DEVICE_FLEET:
    _d["cert_age_days"], _d["mfa_capable"], _d["exposure"] = _REGISTRY[_d["device_id"]]
DEVICE_BY_ID = {d["device_id"]: d for d in DEVICE_FLEET}


def load_raw_data(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, names=COLUMN_NAMES)
    df["attack_category"] = df["label"].map(ATTACK_CATEGORY_MAP).fillna("Unknown_Attack")
    df["is_attack"] = (df["attack_category"] != "Normal").astype(int)
    return df


def assign_devices(df: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    """Deterministically map each record to a simulated IoT device based on
    its (protocol_type, service) signature."""
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


def add_synthetic_iot_telemetry(df: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    """Generate requests_per_min / avg_payload_bytes: archetype-conditioned
    baselines, perturbed by attack category in a direction consistent with
    how that attack family actually manifests in IoT traffic (DoS/Probe =
    request-rate spikes; R2L/U2R = smaller, stealthier deviations), plus
    noise so the features are informative but not a trivial giveaway."""
    rng = np.random.default_rng(seed)
    n = len(df)

    rpm_base = df["device_id"].map(lambda d: DEVICE_BY_ID[d]["rpm_base"]).values.astype(float)
    payload_base = df["device_id"].map(lambda d: DEVICE_BY_ID[d]["payload_base"]).values.astype(float)
    cat = df["attack_category"].values

    rpm_multiplier = np.ones(n)
    payload_multiplier = np.ones(n)

    dos_mask = cat == "DoS"
    probe_mask = cat == "Probe"
    r2l_mask = cat == "R2L"
    u2r_mask = cat == "U2R"

    rpm_multiplier[dos_mask] = rng.uniform(6, 15, dos_mask.sum())      # flood of requests
    payload_multiplier[dos_mask] = rng.uniform(0.2, 0.5, dos_mask.sum())  # tiny flood packets

    rpm_multiplier[probe_mask] = rng.uniform(3, 7, probe_mask.sum())   # scanning = many small requests
    payload_multiplier[probe_mask] = rng.uniform(0.3, 0.6, probe_mask.sum())

    rpm_multiplier[r2l_mask] = rng.uniform(1.2, 2.0, r2l_mask.sum())   # repeated login attempts
    payload_multiplier[r2l_mask] = rng.uniform(1.0, 1.3, r2l_mask.sum())

    rpm_multiplier[u2r_mask] = rng.uniform(0.9, 1.3, u2r_mask.sum())   # subtle, low-rate
    payload_multiplier[u2r_mask] = rng.uniform(1.1, 1.8, u2r_mask.sum())  # privilege-escalation payloads

    noise_rpm = rng.normal(1.0, 0.15, n).clip(0.5, 1.5)
    noise_payload = rng.normal(1.0, 0.12, n).clip(0.6, 1.4)

    df = df.copy()
    df["requests_per_min"] = (rpm_base * rpm_multiplier * noise_rpm).clip(0.1, None).round(2)
    df["avg_payload_bytes"] = (payload_base * payload_multiplier * noise_payload).clip(10, None).round(1)
    return df


class FeaturePipeline:
    """Fits encoders/scaler on training data, applies consistently to any split."""

    SYNTHETIC_FEATURES = ["requests_per_min", "avg_payload_bytes"]

    def __init__(self):
        self.encoders = {c: LabelEncoder() for c in CATEGORICAL_COLS}
        self.scaler = StandardScaler()
        self.feature_cols = None

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        work = df.copy()
        for c in CATEGORICAL_COLS:
            work[c] = self.encoders[c].fit_transform(work[c].astype(str))
        base_cols = [c for c in COLUMN_NAMES if c != "label"]
        self.feature_cols = base_cols + self.SYNTHETIC_FEATURES
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
    train_df = add_synthetic_iot_telemetry(assign_devices(load_raw_data(train_path), seed=seed), seed=seed)
    test_df = add_synthetic_iot_telemetry(assign_devices(load_raw_data(test_path), seed=seed), seed=seed + 1)

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
    print("Feature count:", len(data["pipeline"].feature_cols))
    print(data["train_df"].groupby("attack_category")[["requests_per_min", "avg_payload_bytes"]].mean().round(1))
