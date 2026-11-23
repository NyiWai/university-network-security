"""Hybrid rules + optional Isolation Forest detector."""
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from detector.rules import evaluate_rules

FEATURES = ["failed_logins", "connection_count", "bytes_out", "unique_destinations", "avg_packet_size"]
MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "isolation_forest.joblib"


def train_baseline(seed=42, samples=600):
    rng = np.random.default_rng(seed)
    baseline = np.column_stack([
        rng.poisson(0.3, samples), rng.poisson(25, samples),
        rng.lognormal(11, 0.8, samples), rng.poisson(8, samples),
        rng.normal(700, 180, samples).clip(60, 1500)
    ])
    model = IsolationForest(n_estimators=150, contamination=0.04, random_state=seed)
    model.fit(baseline)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "features": FEATURES}, MODEL_PATH)
    return MODEL_PATH


def analyze_features(features, train_if_missing=True):
    rules = evaluate_rules(features)
    model_result = None
    if not MODEL_PATH.exists() and train_if_missing:
        train_baseline()
    if MODEL_PATH.exists():
        bundle = joblib.load(MODEL_PATH)
        row = np.array([[float(features.get(k, 0)) for k in bundle["features"]]])
        prediction = int(bundle["model"].predict(row)[0])
        score = float(-bundle["model"].score_samples(row)[0])
        model_result = {"anomaly": prediction == -1, "anomaly_score": round(score, 4)}
    return {"rules": rules, "model": model_result,
            "suspicious": bool(rules) or bool(model_result and model_result["anomaly"])}
