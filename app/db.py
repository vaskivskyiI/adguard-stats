"""SQLite storage.

Layout (all aggregate tables are WITHOUT ROWID, keyed by time first):
  hourly      (hour, client, domain) -> queries, blocked, slots   slots = 12-bit mask of active 5-minute slots
  daily       (day, client, domain)  -> queries, blocked, active  active = number of active 5-minute slots
  group_hourly(hour, client, kind, key) -> slots   union of slots over all domains in a category ('c'),
                                                     service ('s') or all non-background domains ('a')
  group_daily (day, client, kind, key)  -> active
  meta_daily  (day, client, kind, key)  -> value   qtype / reason / upstream counts, cache hits, latency sum
`hour` is a UTC epoch (start of hour); `day` is the local date as YYYYMMDD.
Persons and categories are joined at query time, so re-assigning a device or re-categorizing a
domain applies to all history instantly.
"""
import sqlite3
from datetime import date, datetime, timedelta

from . import config

SLOT_SECONDS = 300
SLOT_MINUTES = SLOT_SECONDS // 60

SCHEMA = """
CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS persons(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, color TEXT);
CREATE TABLE IF NOT EXISTS clients(
  id INTEGER PRIMARY KEY, ip TEXT NOT NULL UNIQUE, name TEXT, label TEXT,
  person_id INTEGER REFERENCES persons(id) ON DELETE SET NULL,
  first_seen INTEGER, last_seen INTEGER);
CREATE TABLE IF NOT EXISTS domains(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, service TEXT,
  category TEXT NOT NULL DEFAULT 'Other', autoblock INTEGER NOT NULL DEFAULT 0,
  first_seen INTEGER, first_client INTEGER);
CREATE TABLE IF NOT EXISTS rules(
  pattern TEXT NOT NULL, source TEXT NOT NULL, service TEXT, category TEXT NOT NULL,
  PRIMARY KEY(pattern, source));
CREATE TABLE IF NOT EXISTS hourly(
  hour INTEGER, client_id INTEGER, domain_id INTEGER, queries INTEGER, blocked INTEGER, slots INTEGER,
  PRIMARY KEY(hour, client_id, domain_id)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS daily(
  day INTEGER, client_id INTEGER, domain_id INTEGER, queries INTEGER, blocked INTEGER, active INTEGER,
  PRIMARY KEY(day, client_id, domain_id)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS daily_domain ON daily(domain_id, day);
CREATE TABLE IF NOT EXISTS group_hourly(
  hour INTEGER, client_id INTEGER, kind TEXT, key TEXT, slots INTEGER,
  PRIMARY KEY(hour, client_id, kind, key)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS group_daily(
  day INTEGER, client_id INTEGER, kind TEXT, key TEXT, active INTEGER,
  PRIMARY KEY(day, client_id, kind, key)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS meta_daily(
  day INTEGER, client_id INTEGER, kind TEXT, key TEXT, value INTEGER,
  PRIMARY KEY(day, client_id, kind, key)) WITHOUT ROWID;
"""


def popcount(x):
    return int(x).bit_count() if x else 0


def connect(path=None):
    conn = sqlite3.connect(path or config.DB_PATH, timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.create_function("popcount", 1, popcount, deterministic=True)
    return conn


def init(path=None):
    conn = connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def get_state(conn, key, default=None):
    row = conn.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def set_state(conn, key, value):
    if value is None:
        conn.execute("DELETE FROM state WHERE key=?", (key,))
    else:
        conn.execute("INSERT OR REPLACE INTO state(key, value) VALUES(?, ?)", (key, str(value)))


# --- time helpers -----------------------------------------------------------

def day_int(d: date) -> int:
    return d.year * 10000 + d.month * 100 + d.day


def int_day(v: int) -> date:
    return date(v // 10000, v // 100 % 100, v % 100)


def local_day_of(ts: int) -> int:
    return day_int(datetime.fromtimestamp(ts, config.TZ).date())


def day_bounds(d: date):
    """UTC epoch [start, end) of a local calendar day (DST-safe)."""
    start = datetime(d.year, d.month, d.day, tzinfo=config.TZ)
    nxt = d + timedelta(days=1)
    end = datetime(nxt.year, nxt.month, nxt.day, tzinfo=config.TZ)
    return int(start.timestamp()), int(end.timestamp())
