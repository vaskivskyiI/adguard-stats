"""Runtime settings, read once from environment variables."""
import os
from zoneinfo import ZoneInfo

ADGUARD_URL = os.environ.get("ADGUARD_URL", "http://127.0.0.1:3000").rstrip("/")
ADGUARD_USER = os.environ.get("ADGUARD_USER", "")
ADGUARD_PASSWORD = os.environ.get("ADGUARD_PASSWORD", "")
ADGUARD_VERIFY_TLS = os.environ.get("ADGUARD_VERIFY_TLS", "true").lower() not in ("0", "false", "no")

DB_PATH = os.environ.get("DB_PATH", "/data/stats.db")
POLL_INTERVAL = max(10, int(os.environ.get("POLL_INTERVAL", "60")))
# Hour-level detail (heatmaps, day timelines, hourly charts). Day-level data is kept forever.
HOURLY_RETENTION_DAYS = int(os.environ.get("HOURLY_RETENTION_DAYS", "400"))

DASHBOARD_USER = os.environ.get("DASHBOARD_USER", "admin")
DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "")

TZ = ZoneInfo(os.environ.get("TZ") or "UTC")
