"""Safe, preview-only bandwidth policy layer.

This first milestone deliberately does not execute OS traffic-shaping commands.
It validates policies and produces platform-specific command previews.
"""
import ipaddress
import re
import platform

_IFACE = re.compile(r"^[A-Za-z0-9_.: -]{1,64}$")
MIN_MBPS = 1
MAX_MBPS = 10

def validate_policy(target_ip, upload_interface, download_interface, limit_mbps, direction):
    try:
        ip = ipaddress.ip_address((target_ip or "").strip())
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 address.") from exc
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        raise ValueError("Target must be a private, unicast IPv4 address in an authorized lab.")
    for label, iface in (("Upload interface", upload_interface), ("Download interface", download_interface)):
        if direction in ("Upload", "Both") and label == "Upload interface":
            if not _IFACE.fullmatch((iface or "").strip()):
                raise ValueError("Enter a valid upload interface name.")
        if direction in ("Download", "Both") and label == "Download interface":
            if not _IFACE.fullmatch((iface or "").strip()):
                raise ValueError("Enter a valid download interface name.")
    try:
        rate = int(limit_mbps)
    except (TypeError, ValueError) as exc:
        raise ValueError("Bandwidth limit must be a whole number.") from exc
    if not MIN_MBPS <= rate <= MAX_MBPS:
        raise ValueError(f"Lab limit must be between {MIN_MBPS} and {MAX_MBPS} Mbps.")
    if direction not in {"Upload", "Download", "Both"}:
        raise ValueError("Choose Upload, Download, or Both.")
    return {
        "target_ip": str(ip),
        "upload_interface": (upload_interface or "").strip(),
        "download_interface": (download_interface or "").strip(),
        "limit_mbps": rate,
        "direction": direction,
    }

def build_preview(policy, system=None):
    system = system or platform.system()
    ip = policy["target_ip"]
    rate = policy["limit_mbps"]
    lines = [
        f"Target: {ip}",
        f"Direction: {policy['direction']}",
        f"Limit: {rate} Mbps",
        "MODE: PREVIEW ONLY — no commands are executed.",
        "",
    ]
    if system == "Linux":
        lines += [
            "# Linux gateway concept: shape egress on the interface in each direction.",
            "# Upload: client traffic exits the WAN interface (match source IP).",
            "# Download: traffic exits the LAN interface toward the client (match destination IP).",
            "# A production adapter must preserve/coordinate existing qdiscs and use IFB for",
            "# ingress-only topologies; do not blindly replace existing qdisc configuration.",
        ]
        if policy["direction"] in ("Upload", "Both"):
            lines += [
                f"# Upload egress interface: {policy['upload_interface']}",
                f"tc qdisc add dev {policy['upload_interface']} root handle 1: htb default 30",
                f"tc class add dev {policy['upload_interface']} parent 1: classid 1:1 htb rate 100mbit",
                f"tc class add dev {policy['upload_interface']} parent 1:1 classid 1:10 htb rate {rate}mbit ceil {rate}mbit",
                f"tc filter add dev {policy['upload_interface']} protocol ip parent 1: prio 1 u32 match ip src {ip}/32 flowid 1:10",
            ]
        if policy["direction"] in ("Download", "Both"):
            lines += [
                f"# Download egress interface: {policy['download_interface']}",
                f"tc qdisc add dev {policy['download_interface']} root handle 1: htb default 30",
                f"tc class add dev {policy['download_interface']} parent 1: classid 1:1 htb rate 100mbit",
                f"tc class add dev {policy['download_interface']} parent 1:1 classid 1:10 htb rate {rate}mbit ceil {rate}mbit",
                f"tc filter add dev {policy['download_interface']} protocol ip parent 1: prio 1 u32 match ip dst {ip}/32 flowid 1:10",
            ]
        lines += [
            "",
            "# Rollback concept (ONLY on dedicated lab interfaces with no pre-existing qdisc):",
            *([f"tc qdisc del dev {policy['upload_interface']} root"] if policy["direction"] in ("Upload", "Both") else []),
            *([f"tc qdisc del dev {policy['download_interface']} root"] if policy["direction"] in ("Download", "Both") else []),
        ]
        lines += ["", "NOTE: this is an illustrative preview, not a safe-to-run script."]
    elif system == "Windows":
        lines += [
            "# Windows QoS policy preview. Windows QoS policy is host-originated traffic policy;",
            "# it does NOT shape arbitrary third-party devices passing through this PC.",
            "# Elevated PowerShell and Windows policy validation are required.",
        ]
        if policy["direction"] in ("Upload", "Both"):
            lines.append(
                f'New-NetQosPolicy -Name "UniversityLab-{ip}-Upload" -IPDstPrefix "{ip}/32" '
                f'-ThrottleRateActionBitsPerSecond {rate * 1000000}'
            )
        if policy["direction"] in ("Download", "Both"):
            lines.append("# Download shaping for another LAN client is not provided by this host policy preview.")
        lines += [
            "",
            f'# Rollback example after verifying the exact policy name:',
            f'Remove-NetQosPolicy -Name "UniversityLab-{ip}-Upload"',
            "",
            "NOTE: preview only; no Windows QoS policy is created or removed.",
        ]
    else:
        lines.append(f"Unsupported platform for adapter preview: {system}")
    return "\\n".join(lines)

def get_platform_capabilities(system=None):
    system = system or platform.system()
    if system == "Linux":
        return {
            "platform": system,
            "mode": "preview-only",
            "upload": "Preview available: gateway WAN egress, match source IP.",
            "download": "Preview available: gateway LAN egress, match destination IP.",
            "apply": False,
            "reason": "Apply is intentionally disabled until gateway topology, existing qdiscs, and rollback are verified in a dedicated lab.",
        }
    if system == "Windows":
        return {
            "platform": system,
            "mode": "preview-only",
            "upload": "Windows QoS preview for host-originated traffic only.",
            "download": "Not supported for shaping another LAN device through this Windows host.",
            "apply": False,
            "reason": "Windows QoS policy is not a gateway traffic shaper. Use a supported router/firewall QoS API for other devices.",
        }
    return {"platform": system, "mode": "unsupported", "upload": "Unsupported", "download": "Unsupported", "apply": False, "reason": "Unsupported OS."}
