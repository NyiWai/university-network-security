import platform
import subprocess
import re
from datetime import datetime, timezone


def discover_devices():
    system = platform.system()
    devices = []
    command = ["ip", "neigh", "show"] if system == "Linux" else ["arp", "-a"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        for line in result.stdout.splitlines():
            if system == "Linux":
                parts = line.split()
                if not parts:
                    continue
                ip = parts[0]
                iface = parts[parts.index("dev") + 1] if "dev" in parts and parts.index("dev") + 1 < len(parts) else ""
                mac = parts[parts.index("lladdr") + 1].lower() if "lladdr" in parts and parts.index("lladdr") + 1 < len(parts) else ""
                state = parts[-1] if len(parts) > 1 else "UNKNOWN"
            else:
                match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s+(\w+)", line)
                if not match:
                    continue
                ip, mac, state = match.groups()
                mac, iface = mac.replace("-", ":").lower(), ""
            devices.append({"ip": ip, "mac": mac, "interface": iface, "state": state,
                            "discovered_at": datetime.now(timezone.utc).isoformat()})
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Neighbor discovery failed: {exc}") from exc
    return devices
