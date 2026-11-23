import json
from pathlib import Path


def read_eve_alerts(path, limit=200):
    file = Path(path).expanduser()
    if not file.exists():
        return []
    events = []
    with file.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("event_type") == "alert":
                alert = item.get("alert", {})
                events.append({"timestamp": item.get("timestamp", ""),
                               "source": "suricata", "src_ip": item.get("src_ip", ""),
                               "dst_ip": item.get("dest_ip", ""),
                               "event_type": alert.get("signature", "Suricata alert"),
                               "severity": {1: "HIGH", 2: "MEDIUM", 3: "LOW"}.get(alert.get("severity"), "INFO"),
                               "score": max(0, 4 - int(alert.get("severity", 4))) * 25,
                               "description": f"SID {alert.get('signature_id', 'unknown')}"})
    return events[-limit:]
