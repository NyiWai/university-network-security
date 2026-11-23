"""Windows Firewall adapter status. Rule creation is not automatic."""
import platform
import subprocess


def get_firewall_status():
    if platform.system() != "Windows":
        return {"supported": False, "message": "This adapter runs on Windows only."}
    result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"],
                            capture_output=True, text=True, timeout=10, check=False)
    return {"supported": True, "returncode": result.returncode,
            "output": result.stdout, "error": result.stderr}
