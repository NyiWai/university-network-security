def evaluate_rules(features):
    alerts = []
    failed = int(features.get("failed_logins", 0))
    connections = int(features.get("connection_count", 0))
    bytes_out = int(features.get("bytes_out", 0))
    unique_dst = int(features.get("unique_destinations", 0))
    if failed >= 8:
        alerts.append({"event_type": "Possible brute-force activity", "severity": "HIGH", "score": 90,
                       "description": f"Observed {failed} failed login attempts in the sample window."})
    if connections >= 150:
        alerts.append({"event_type": "Unusual connection volume", "severity": "MEDIUM", "score": 65,
                       "description": f"Observed {connections} connections in the sample window."})
    if bytes_out >= 50_000_000:
        alerts.append({"event_type": "Unusual outbound transfer", "severity": "HIGH", "score": 85,
                       "description": f"Observed {bytes_out:,} outbound bytes in the sample window."})
    if unique_dst >= 80:
        alerts.append({"event_type": "High destination diversity", "severity": "MEDIUM", "score": 60,
                       "description": f"Contacted {unique_dst} distinct destinations in the sample window."})
    return alerts
