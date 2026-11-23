import sqlite3
from pathlib import Path
from contextlib import contextmanager

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "data" / "network_security.db"


@contextmanager
def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def initialize_database():
    with get_connection() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            mac TEXT NOT NULL DEFAULT '',
            interface TEXT NOT NULL DEFAULT '',
            state TEXT NOT NULL DEFAULT 'UNKNOWN',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            UNIQUE(ip, mac, interface)
        );
        CREATE TABLE IF NOT EXISTS allowed_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL UNIQUE,
            device_name TEXT NOT NULL,
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS access_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT NOT NULL,
            device_name TEXT DEFAULT '',
            action TEXT NOT NULL,
            reason TEXT DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL DEFAULT 'system',
            src_ip TEXT DEFAULT '',
            dst_ip TEXT DEFAULT '',
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'INFO',
            score REAL NOT NULL DEFAULT 0,
            description TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'OPEN',
            features_json TEXT DEFAULT '{}'
        );
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_status ON security_events(status);
        CREATE TABLE IF NOT EXISTS traffic_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            interface TEXT NOT NULL,
            src_ip TEXT DEFAULT '',
            dst_ip TEXT DEFAULT '',
            protocol TEXT DEFAULT 'OTHER',
            packet_length INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS bandwidth_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_ip TEXT NOT NULL,
            upload_interface TEXT DEFAULT '',
            download_interface TEXT DEFAULT '',
            limit_mbps INTEGER NOT NULL,
            direction TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'PENDING',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            approved_at TEXT DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            notes TEXT DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_bandwidth_status ON bandwidth_policies(status);
        """)


def save_devices(devices):
    with get_connection() as db:
        for d in devices:
            ip = str(d.get("ip", ""))
            mac = (d.get("mac") or "").lower().replace("-", ":")
            interface = d.get("interface") or ""
            seen = d.get("discovered_at") or d.get("last_seen") or d.get("first_seen")
            if not ip or not seen:
                continue
            db.execute("""
                INSERT INTO devices(ip, mac, interface, state, first_seen, last_seen)
                VALUES(?,?,?,?,?,?)
                ON CONFLICT(ip, mac, interface) DO UPDATE SET
                    state=excluded.state, last_seen=excluded.last_seen
            """, (ip, mac, interface, d.get("state", "UNKNOWN"), seen, seen))


def get_all_devices():
    with get_connection() as db:
        return [dict(r) for r in db.execute("SELECT * FROM devices ORDER BY last_seen DESC")]


def add_access_event(mac, name, action, reason):
    with get_connection() as db:
        db.execute("INSERT INTO access_events(mac,device_name,action,reason) VALUES(?,?,?,?)",
                   (mac, name, action, reason))


def save_security_event(event):
    with get_connection() as db:
        cur = db.execute("""
            INSERT INTO security_events(timestamp,source,src_ip,dst_ip,event_type,severity,score,description,status,features_json)
            VALUES(?,?,?,?,?,?,?,?,?,?)
        """, (event.get("timestamp"), event.get("source", "system"), event.get("src_ip", ""),
              event.get("dst_ip", ""), event.get("event_type", "UNKNOWN"), event.get("severity", "INFO"),
              float(event.get("score", 0)), event.get("description", ""), event.get("status", "OPEN"),
              event.get("features_json", "{}")))
        return cur.lastrowid


def get_security_events(limit=500):
    with get_connection() as db:
        return [dict(r) for r in db.execute("SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,))]


def update_event_status(event_id, status):
    if status not in {"OPEN", "ACKNOWLEDGED", "CLOSED"}:
        raise ValueError("Invalid event status")
    with get_connection() as db:
        db.execute("UPDATE security_events SET status=? WHERE id=?", (status, int(event_id)))


def get_access_events(limit=200):
    with get_connection() as db:
        return [dict(r) for r in db.execute("SELECT * FROM access_events ORDER BY id DESC LIMIT ?", (limit,))]


def get_traffic_samples(limit=1000):
    with get_connection() as db:
        return [dict(r) for r in db.execute("SELECT * FROM traffic_samples ORDER BY id DESC LIMIT ?", (limit,))]


def create_bandwidth_policy(policy):
    with get_connection() as db:
        cur = db.execute("""INSERT INTO bandwidth_policies
            (target_ip, upload_interface, download_interface, limit_mbps, direction, status, notes)
            VALUES(?,?,?,?,?,'PENDING',?)""",
            (policy['target_ip'], policy['upload_interface'], policy['download_interface'],
             policy['limit_mbps'], policy['direction'], 'Preview-only lab policy'))
        return cur.lastrowid


def get_bandwidth_policies(limit=200):
    with get_connection() as db:
        return [dict(r) for r in db.execute(
            "SELECT * FROM bandwidth_policies ORDER BY id DESC LIMIT ?", (limit,))]


def update_bandwidth_policy_status(policy_id, status):
    allowed = {'PENDING', 'APPROVED', 'PREVIEWED', 'ROLLED_BACK'}
    if status not in allowed:
        raise ValueError('Invalid bandwidth policy status')
    with get_connection() as db:
        row = db.execute('SELECT id FROM bandwidth_policies WHERE id=?', (int(policy_id),)).fetchone()
        if row is None:
            raise ValueError('Bandwidth policy not found')
        if status == 'APPROVED':
            db.execute("UPDATE bandwidth_policies SET status=?, approved_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                       (status, int(policy_id)))
        else:
            db.execute("UPDATE bandwidth_policies SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                       (status, int(policy_id)))
