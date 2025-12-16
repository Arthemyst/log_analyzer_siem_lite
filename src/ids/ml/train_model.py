import json
import logging
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from feature_config import FEATURE_COLUMNS

FLOWS_FILE = "flows/flows_capture.jsonl"
ARTIFACTS_DIR = "src/ids/ml/artifacts"

logger = logging.getLogger("train_model")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)


def load_flows(path: str) -> list:
    flows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            flows.append(json.loads(line))
    return flows


def build_feature_matrix(flows: list) -> np.ndarray:
    X = []
    for flow in flows:
        row = []
        for col in FEATURE_COLUMNS:
            row.append(float(flow.get(col, 0)))
        X.append(row)
    return np.array(X)


def main():
    logger.info("Loading flows...")
    flows = load_flows(FLOWS_FILE)

    if len(flows) < 50:
        logger.warning("Not enough flows to train.")
        return

    logger.info(f"Loaded {len(flows)} flows.")

    X = build_feature_matrix(flows)

    logger.info("Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    logger.info("Training IsolationForest...")
    model = IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
        n_jobs=1,
    )
    model.fit(X_scaled)

    os.makedirs(ARTIFACTS_DIR, exist_ok=True)

    joblib.dump(scaler, os.path.join(ARTIFACTS_DIR, "scaler.joblib"))
    joblib.dump(model, os.path.join(ARTIFACTS_DIR, "isolation_forest.joblib"))

    with open(f"{ARTIFACTS_DIR}/features.json", "w") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)

    logger.info("Model training complete.")
    logger.info(f"Artifacts saved to: {ARTIFACTS_DIR}")


if __name__ == "__main__":
    main()
