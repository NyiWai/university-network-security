"""Opt-in packet metadata capture. Payloads are never stored."""
from datetime import datetime, timezone


def capture_metadata(interface, packet_count=100, timeout=15):
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
    except ImportError as exc:
        raise RuntimeError("Scapy is not installed") from exc
    if not interface or len(interface) > 15:
        raise ValueError("Select a valid interface")
    records = []
    def handle(pkt):
        if IP not in pkt:
            return
        proto = "OTHER"
        if TCP in pkt:
            proto = "TCP"
        elif UDP in pkt:
            proto = "UDP"
        elif ICMP in pkt:
            proto = "ICMP"
        records.append({"timestamp": datetime.now(timezone.utc).isoformat(),
                        "interface": interface, "src_ip": pkt[IP].src,
                        "dst_ip": pkt[IP].dst, "protocol": proto,
                        "packet_length": len(pkt)})
    sniff(iface=interface, prn=handle, store=False, count=int(packet_count), timeout=int(timeout))
    return records
