import json
from core.database import save_security_event
from detector.detector import analyze_features


def process_feature_sample(sample, source="simulation"):
    features = sample["features"]
    result = analyze_features(features)
    generated = []
    if result["rules"]:
        alerts = result["rules"]
    elif result["model"] and result["model"]["anomaly"]:
        alerts = [{"event_type": "ML anomaly detected", "severity": "MEDIUM", "score": 60,
                   "description": f"Isolation Forest anomaly score: {result['model']['anomaly_score']}"}]
    else:
        alerts = [{"event_type": "Normal activity", "severity": "INFO", "score": 0,
                   "description": "No configured rule threshold was exceeded."}]
    for alert in alerts:
        event = {"timestamp": sample.get("timestamp"), "source": source,
                 "event_type": alert["event_type"], "severity": alert["severity"],
                 "score": alert["score"], "description": alert["description"],
                 "features_json": json.dumps(features)}
        save_security_event(event)
        generated.append(event)
    return result, generated
