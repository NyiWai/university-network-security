import socket
import psutil


def get_network_interfaces():
    result = []
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for name, items in addresses.items():
        stat = stats.get(name)
        row = {"name": name, "is_up": bool(stat and stat.isup), "speed": stat.speed if stat else 0,
               "ipv4": [], "ipv6": [], "mac": None}
        for item in items:
            if item.family == socket.AF_INET:
                row["ipv4"].append(item.address)
            elif item.family == socket.AF_INET6:
                row["ipv6"].append(item.address.split("%")[0])
            elif item.family == getattr(psutil, "AF_LINK", object()):
                row["mac"] = item.address
        result.append(row)
    return result
