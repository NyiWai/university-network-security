"""NetworkManager hotspot helper. Inspection only; creation/removal is intentionally manual."""
import subprocess


def get_wifi_status(interface="wlan0"):
    result = subprocess.run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"],
                            capture_output=True, text=True, timeout=10, check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "nmcli failed")
    return [line for line in result.stdout.splitlines() if line.startswith(interface + ":")]


def read_dnsmasq_leases(paths=None):
    paths = paths or ["/var/lib/NetworkManager/dnsmasq-wlan0.leases", "/var/lib/misc/dnsmasq.leases"]
    leases = []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) >= 5:
                        leases.append({"expiry": parts[0], "mac": parts[1].lower(),
                                       "ip": parts[2], "hostname": parts[3], "client_id": parts[4]})
        except (FileNotFoundError, PermissionError):
            continue
    return leases
