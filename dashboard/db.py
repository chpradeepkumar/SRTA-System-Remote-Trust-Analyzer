import sqlite3
import json
import os
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "srta.db")


def _conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)


def init_db():
    conn = _conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS state (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER,
            payload TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def set_state(key: str, value) -> None:
    v = json.dumps(value)
    conn = _conn()
    cur = conn.cursor()
    cur.execute("REPLACE INTO state (key, value) VALUES (?,?)", (key, v))
    conn.commit()
    conn.close()


def get_state(key: str):
    conn = _conn()
    cur = conn.cursor()
    cur.execute("SELECT value FROM state WHERE key=?", (key,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    try:
        return json.loads(row[0])
    except Exception:
        return None


def save_scan(results):
    payload = {"ts": int(time.time()), "results": results}
    conn = _conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (ts, payload) VALUES (?,?)", (payload["ts"], json.dumps(payload)))
    conn.commit()
    conn.close()
    # also keep latest in state for quick access
    set_state("last_scan", payload)
    return payload["ts"]


def get_last_scan():
    payload = get_state("last_scan")
    if not payload:
        return None
    return payload
