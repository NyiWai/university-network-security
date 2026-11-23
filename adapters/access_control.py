import re
from core.database import get_connection, add_access_event, get_access_events

_MAC = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def normalize_mac(mac):
    value = (mac or "").strip().lower().replace("-", ":")
    if not _MAC.fullmatch(value):
        raise ValueError("Enter a valid MAC address (AA:BB:CC:DD:EE:FF).")
    return value


def initialize_access_control():
    # Tables are created centrally by initialize_database().
    return None


def allow_device(mac, device_name, description=""):
    mac = normalize_mac(mac)
    name = (device_name or "").strip()
    if not name:
        raise ValueError("Device name is required.")
    with get_connection() as db:
        db.execute("""INSERT INTO allowed_devices(mac,device_name,description) VALUES(?,?,?)
        ON CONFLICT(mac) DO UPDATE SET device_name=excluded.device_name, description=excluded.description""",
                   (mac, name, (description or "").strip()))
    add_access_event(mac, name, "ALLOWED", "Added or updated in application allow-list")


def revoke_device(mac):
    mac = normalize_mac(mac)
    with get_connection() as db:
        row = db.execute("SELECT device_name FROM allowed_devices WHERE mac=?", (mac,)).fetchone()
        if row is None:
            return False
        db.execute("DELETE FROM allowed_devices WHERE mac=?", (mac,))
    add_access_event(mac, row["device_name"], "REVOKED", "Removed from application allow-list")
    return True


def is_device_allowed(mac):
    mac = normalize_mac(mac)
    with get_connection() as db:
        return db.execute("SELECT 1 FROM allowed_devices WHERE mac=?", (mac,)).fetchone() is not None


def get_allowed_devices():
    with get_connection() as db:
        return [dict(r) for r in db.execute("SELECT * FROM allowed_devices ORDER BY created_at DESC")]
