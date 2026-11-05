"""Polls the AdGuard Home query log and folds it into the aggregate tables (see db.py).

The query log is read newest-first. A "run" walks pages from the newest entry back to the
cursor (newest entry already ingested). Each page is ingested in one transaction together with
the run position, so a crash or restart never counts an entry twice.
"""
import base64
import json
import logging
import ssl
import threading
import time
from collections import Counter, defaultdict
from datetime import datetime
from functools import lru_cache
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from . import categories, config, db

log = logging.getLogger("collector")

PAGE_SIZE = 500
PAGES_PER_CHUNK = 100          # pages ingested before dirty days are re-aggregated
SERVICES_REFRESH = 24 * 3600
BLOCK_REASONS = {
    "FilteredBlackList", "FilteredSafeBrowsing", "FilteredParental",
    "FilteredInvalid", "FilteredBlockedService",
}


def parse_time(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


class AdGuard:
    def __init__(self):
        self.ctx = None if config.ADGUARD_VERIFY_TLS else ssl._create_unverified_context()
        self.auth = None
        if config.ADGUARD_USER:
            raw = f"{config.ADGUARD_USER}:{config.ADGUARD_PASSWORD}".encode()
            self.auth = "Basic " + base64.b64encode(raw).decode()

    def get(self, path, params=None):
        url = config.ADGUARD_URL + path + ("?" + urlencode(params) if params else "")
        req = Request(url, headers={"Accept": "application/json"})
        if self.auth:
            req.add_header("Authorization", self.auth)
        with urlopen(req, timeout=60, context=self.ctx) as r:
            return json.load(r)

    def querylog(self, older_than=""):
        return self.get("/control/querylog", {"older_than": older_than, "limit": PAGE_SIZE})


class Ingester:
    """Turns raw query-log entries into aggregate rows. Holds id caches; one per writer connection."""

    def __init__(self, conn):
        self.conn = conn
        self.reload_rules()
        self.clients = {ip: cid for cid, ip in conn.execute("SELECT id, ip FROM clients")}
        self.domains = {n: (did, ab) for did, n, ab in conn.execute("SELECT id, name, autoblock FROM domains")}

    def reload_rules(self):
        self.matcher = categories.Matcher(self.conn)
        self.site_of = lru_cache(maxsize=200_000)(self.matcher.site_key)

    def _client(self, ip, name):
        cid = self.clients.get(ip)
        if cid is None:
            cid = self.conn.execute("INSERT INTO clients(ip, name) VALUES(?, ?)", (ip, name or None)).lastrowid
            self.clients[ip] = cid
        return cid

    def _domain(self, site, adblocked):
        hit = self.domains.get(site)
        if hit is None:
            service, category = self.matcher.classify(site, adblocked)
            did = self.conn.execute(
                "INSERT INTO domains(name, service, category, autoblock) VALUES(?,?,?,?)",
                (site, service, category, int(adblocked)),
            ).lastrowid
            self.domains[site] = (did, adblocked)
            return did
        did, ab = hit
        if adblocked and not ab:
            service, category = self.matcher.classify(site, True)
            self.conn.execute("UPDATE domains SET autoblock=1, service=?, category=? WHERE id=?", (service, category, did))
            self.domains[site] = (did, True)
        return did

    def ingest(self, entries):
        """Add entries (already parsed: list of (ts, entry)). Returns the set of touched local days."""
        hourly = defaultdict(lambda: [0, 0, 0])
        meta = Counter()
        day_of_hour = {}
        dom_first = {}
        cli_span = {}
        names = {}
        for ts, e in entries:
            q = e.get("question") or {}
            name = categories.normalize(q.get("name") or q.get("host") or "")
            if not name:
                continue
            ip = e.get("client") or "unknown"
            info = e.get("client_info") or {}
            if info.get("name"):
                names[ip] = info["name"]
            cid = self._client(ip, info.get("name"))
            reason = e.get("reason") or ""
            did = self._domain(self.site_of(name), reason == "FilteredBlackList")

            t = int(ts)
            hour = t - t % 3600
            a = hourly[(hour, cid, did)]
            a[0] += 1
            a[1] += reason in BLOCK_REASONS
            a[2] |= 1 << ((t - hour) // db.SLOT_SECONDS)

            day = day_of_hour.get(hour)
            if day is None:
                day = day_of_hour[hour] = db.local_day_of(hour)
            meta[(day, cid, "qtype", q.get("type") or "?")] += 1
            meta[(day, cid, "reason", reason or "?")] += 1
            if e.get("upstream"):
                meta[(day, cid, "upstream", e["upstream"])] += 1
            if e.get("cached"):
                meta[(day, cid, "perf", "cached")] += 1
            try:
                meta[(day, cid, "perf", "elapsed_us")] += int(float(e.get("elapsedMs") or 0) * 1000)
                meta[(day, cid, "perf", "timed")] += 1
            except ValueError:
                pass

            if did not in dom_first or t < dom_first[did][0]:
                dom_first[did] = (t, cid)
            lo, hi = cli_span.get(cid, (t, t))
            cli_span[cid] = (min(lo, t), max(hi, t))

        c = self.conn
        c.executemany(
            "INSERT INTO hourly VALUES(?,?,?,?,?,?) ON CONFLICT(hour, client_id, domain_id) DO UPDATE SET "
            "queries=queries+excluded.queries, blocked=blocked+excluded.blocked, slots=slots|excluded.slots",
            [(*k, *v) for k, v in hourly.items()],
        )
        c.executemany(
            "INSERT INTO meta_daily VALUES(?,?,?,?,?) ON CONFLICT(day, client_id, kind, key) DO UPDATE SET "
            "value=value+excluded.value",
            [(*k, v) for k, v in meta.items()],
        )
        c.executemany(
            "UPDATE domains SET first_seen=?, first_client=? WHERE id=? AND (first_seen IS NULL OR first_seen>?)",
            [(t, cid, did, t) for did, (t, cid) in dom_first.items()],
        )
        c.executemany(
            "UPDATE clients SET first_seen=MIN(COALESCE(first_seen, ?), ?), last_seen=MAX(COALESCE(last_seen, ?), ?) WHERE id=?",
            [(lo, lo, hi, hi, cid) for cid, (lo, hi) in cli_span.items()],
        )
        c.executemany("UPDATE clients SET name=? WHERE ip=?", [(n, ip) for ip, n in names.items()])
        return set(day_of_hour.values())


def rebuild_day(conn, day: int):
    """Recompute daily, group_hourly and group_daily for one local day from hourly."""
    start, end = db.day_bounds(db.int_day(day))
    conn.execute("DELETE FROM daily WHERE day=?", (day,))
    conn.execute(
        "INSERT INTO daily SELECT ?, client_id, domain_id, SUM(queries), SUM(blocked), SUM(popcount(slots)) "
        "FROM hourly WHERE hour>=? AND hour<? GROUP BY client_id, domain_id",
        (day, start, end),
    )
    rebuild_groups(conn, day, start, end)


def rebuild_groups(conn, day, start, end):
    acc = defaultdict(int)
    for hour, cid, slots, service, category in conn.execute(
        "SELECT h.hour, h.client_id, h.slots, d.service, d.category FROM hourly h "
        "JOIN domains d ON d.id=h.domain_id WHERE h.hour>=? AND h.hour<?",
        (start, end),
    ):
        acc[(hour, cid, "c", category)] |= slots
        if service:
            acc[(hour, cid, "s", service)] |= slots
        if category not in categories.BACKGROUND:
            acc[(hour, cid, "a", "")] |= slots
    totals = Counter()
    for (hour, cid, kind, key), slots in acc.items():
        totals[(cid, kind, key)] += slots.bit_count()
    conn.execute("DELETE FROM group_hourly WHERE hour>=? AND hour<?", (start, end))
    conn.executemany("INSERT INTO group_hourly VALUES(?,?,?,?,?)", [(*k, v) for k, v in acc.items()])
    conn.execute("DELETE FROM group_daily WHERE day=?", (day,))
    conn.executemany("INSERT INTO group_daily VALUES(?,?,?,?,?)", [(day, *k, v) for k, v in totals.items()])


class Collector:
    def __init__(self):
        self.conn = db.init()
        self.api = AdGuard()
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.regroup_days = []
        self.status = {
            "last_poll": None, "last_success": None, "last_error": None,
            "ingested_total": 0, "backfilling": False, "regroup_pending": 0,
        }
        self._next_services = 0
        self._next_prune = 0
        with self.lock:
            categories.replace_rules(self.conn, "builtin", categories.builtin_rules())
            self._apply_rule_change()
            self.conn.commit()

    # --- categorization ----------------------------------------------------

    def _apply_rule_change(self):
        """Call with lock held after the rules table changed."""
        self.ingester = Ingester(self.conn)
        if categories.recategorize_domains(self.conn):
            self.schedule_regroup()

    def rules_changed(self):
        with self.lock:
            self._apply_rule_change()
            self.conn.commit()
        self.wake.set()

    def schedule_regroup(self):
        """Re-derive category/service time for every day that still has hour-level data."""
        row = self.conn.execute("SELECT MIN(hour), MAX(hour) FROM hourly").fetchone()
        if row[0] is None:
            return
        first, last = db.local_day_of(row[0]), db.local_day_of(row[1])
        days = [d for (d,) in self.conn.execute(
            "SELECT DISTINCT day FROM daily WHERE day BETWEEN ? AND ? ORDER BY day DESC", (first, last))]
        self.regroup_days = days
        self.status["regroup_pending"] = len(days)

    def _refresh_services(self):
        try:
            payload = self.api.get("/control/blocked_services/all")
        except Exception as ex:  # older AdGuard Home versions lack this endpoint
            log.warning("blocked services catalogue unavailable: %s", ex)
            return
        rules = categories.adguard_rules(payload)
        if rules:
            with self.lock:
                categories.replace_rules(self.conn, "adguard", rules)
                self._apply_rule_change()
                self.conn.commit()
            log.info("loaded %d AdGuard service rules", len(rules))

    # --- polling -----------------------------------------------------------

    def _dirty(self):
        v = db.get_state(self.conn, "dirty_days", "")
        return {int(x) for x in v.split(",") if x}

    def _flush_dirty(self):
        dirty = self._dirty()
        for d in sorted(dirty):
            rebuild_day(self.conn, d)
        db.set_state(self.conn, "dirty_days", None)
        self.conn.commit()

    def poll(self):
        """Ingest up to PAGES_PER_CHUNK pages. Returns True if more pages are waiting."""
        c = self.conn
        with self.lock:
            run_top = db.get_state(c, "run_top")
            if run_top is None:
                page = self.api.querylog()
                data = page.get("data") or []
                if not data:
                    return False
                top = parse_time(data[0]["time"])
                cursor = float(db.get_state(c, "cursor", "0"))
                if top <= cursor:
                    return False
                db.set_state(c, "run_top", top)
                db.set_state(c, "run_stop", cursor)
                db.set_state(c, "run_older", "")
                c.commit()
        more = True
        for _ in range(PAGES_PER_CHUNK):
            with self.lock:
                top = float(db.get_state(c, "run_top"))
                stop = float(db.get_state(c, "run_stop"))
                older = db.get_state(c, "run_older", "")
            page = self.api.querylog(older)
            data = page.get("data") or []
            batch, finished = [], not data or not page.get("oldest")
            for e in data:
                ts = parse_time(e["time"])
                if ts <= stop:
                    finished = True
                    break
                if ts <= top:
                    batch.append((ts, e))
            with self.lock:
                days = self.ingester.ingest(batch)
                db.set_state(c, "dirty_days", ",".join(map(str, self._dirty() | days)))
                if finished:
                    db.set_state(c, "cursor", top)
                    for k in ("run_top", "run_stop", "run_older"):
                        db.set_state(c, k, None)
                else:
                    db.set_state(c, "run_older", page["oldest"])
                c.commit()
            self.status["ingested_total"] += len(batch)
            if finished:
                more = False
                break
        with self.lock:
            self._flush_dirty()
        self.status["backfilling"] = more
        return more

    def prune(self):
        cutoff = int(time.time()) - config.HOURLY_RETENTION_DAYS * 86400
        with self.lock:
            self.conn.execute("DELETE FROM hourly WHERE hour<?", (cutoff,))
            self.conn.execute("DELETE FROM group_hourly WHERE hour<?", (cutoff,))
            self.conn.commit()
            self.conn.execute("PRAGMA optimize")

    def _regroup_some(self, n=7):
        for _ in range(min(n, len(self.regroup_days))):
            day = self.regroup_days.pop(0)
            start, end = db.day_bounds(db.int_day(day))
            with self.lock:
                rebuild_groups(self.conn, day, start, end)
                self.conn.commit()
        self.status["regroup_pending"] = len(self.regroup_days)

    def run_forever(self):
        with self.lock:
            self._flush_dirty()  # finish aggregation interrupted by a restart
        while True:
            now = time.time()
            more = False
            try:
                if now >= self._next_services:
                    self._next_services = now + SERVICES_REFRESH
                    self._refresh_services()
                self.status["last_poll"] = now
                more = self.poll()
                self.status["last_success"] = time.time()
                self.status["last_error"] = None
                if now >= self._next_prune:
                    self._next_prune = now + 6 * 3600
                    self.prune()
            except Exception as ex:
                log.exception("poll failed")
                self.status["last_error"] = f"{type(ex).__name__}: {ex}"
            try:
                self._regroup_some()
            except Exception:
                log.exception("regroup failed")
            if not more and not self.regroup_days:
                self.wake.wait(config.POLL_INTERVAL)
                self.wake.clear()

    def start(self):
        threading.Thread(target=self.run_forever, name="collector", daemon=True).start()
