import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "network_security.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                mac TEXT,
                interface TEXT,
                state TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(ip, mac, interface)
            )
        """)


def save_devices(devices):
    with get_connection() as connection:
        for device in devices:
            connection.execute("""
                INSERT INTO devices (
                    ip, mac, interface, state, first_seen, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?)

                ON CONFLICT(ip, mac, interface)
                DO UPDATE SET
                    state = excluded.state,
                    last_seen = excluded.last_seen
            """, (
                device["ip"],
                device["mac"] or "",
                device["interface"] or "",
                device["state"],
                device["discovered_at"],
                device["discovered_at"]
            ))


def get_all_devices():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT *
            FROM devices
            ORDER BY last_seen DESC
        """).fetchall()

    return [dict(row) for row in rows]
