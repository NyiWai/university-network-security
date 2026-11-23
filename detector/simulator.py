from datetime import datetime, timezone
import random


def generate_scenario(name):
    normal = {"failed_logins": 0, "connection_count": 22, "bytes_out": 180000,
              "unique_destinations": 7, "avg_packet_size": 720}
    scenarios = {
        "Normal activity": normal,
        "Brute-force simulation": {**normal, "failed_logins": 15, "connection_count": 75},
        "Unusual data transfer": {**normal, "bytes_out": 85_000_000, "avg_packet_size": 1350},
        "Port / destination sweep simulation": {**normal, "connection_count": 220, "unique_destinations": 110},
    }
    features = dict(scenarios[name])
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "features": features}
