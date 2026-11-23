"""Safe nftables ruleset generator and validator. Does not apply rules."""
import ipaddress
import re
import subprocess

TABLE_NAME = "university_nac"


def validate_interface(interface):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", interface or ""):
        raise ValueError("Invalid interface name")
    return interface


def validate_private_network(network):
    net = ipaddress.ip_network(network, strict=False)
    if net.version != 4 or not net.is_private or net.num_addresses > 256:
        raise ValueError("Use a private IPv4 test subnet containing at most 256 addresses")
    return net


def generate_ruleset(interface, network):
    iface = validate_interface(interface)
    net = validate_private_network(network)
    # Non-enforcing counter-only chain: no changes to system policy or existing chains.
    return f'''table inet {TABLE_NAME} {{
    chain forward {{
        type filter hook forward priority 10; policy accept;
        iifname "{iface}" ip saddr {net} counter comment "University NAC test traffic observed"
    }}
}}\n'''


def validate_ruleset(ruleset):
    result = subprocess.run(["nft", "-c", "-f", "-"], input=ruleset, capture_output=True,
                         text=True, timeout=10, check=False)
    return {"valid": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}
