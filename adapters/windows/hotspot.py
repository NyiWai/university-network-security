"""Windows Mobile Hotspot status placeholder; OS settings remain user-controlled."""
import platform
import subprocess


def get_network_status():
    if platform.system() != "Windows":
        return {"supported": False, "message": "Windows only."}
    result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True,
                           text=True, timeout=10, check=False)
    return {"supported": True, "output": result.stdout, "error": result.stderr}
