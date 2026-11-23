import ipaddress
from datetime import datetime, timezone
import psutil


def get_ipv4_networks(max_hosts=256):
    found = []
    for name, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family != __import__("socket").AF_INET or not address.netmask:
                continue
            try:
                network = ipaddress.IPv4Network(f"{address.address}/{address.netmask}", strict=False)
                if network.is_private and not network.is_loopback and not network.is_link_local and network.num_addresses <= max_hosts:
                    found.append({"interface": name, "ip": address.address, "network": str(network)})
            except ValueError:
                pass
    return found


def scan_network(network_cidr, interface, timeout=3):
    network = ipaddress.ip_network(network_cidr, strict=False)
    if network.version != 4 or not network.is_private or network.num_addresses > 256:
        raise ValueError("Only private IPv4 test subnets with at most 256 addresses are supported.")
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError as exc:
        raise RuntimeError("Scapy is not installed. Install requirements first.") from exc
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
    answered, _ = srp(packet, iface=interface, timeout=timeout, retry=1, verbose=False)
    now = datetime.now(timezone.utc).isoformat()
    return [{"ip": r.psrc, "mac": r.hwsrc.lower(), "interface": interface,
             "state": "REACHABLE", "discovered_at": now} for _, r in answered]
