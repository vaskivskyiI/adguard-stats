"""Polls the AdGuard Home query log and folds it into the aggregate tables (see db.py).

The query log is read newest-first. A "run" walks pages from the newest entry back to the
cursor (newest entry already ingested). Each page is ingested in one transaction together with
the run position, so a crash or restart never counts an entry twice.

Until the whole log has been read once ("history"), a run continues past the cursor to the end
of the log and also imports entries older than `floor` (the oldest entry already ingested).

AdGuard pages with `older_than=<time of the last entry>`, which it finds by binary search for that
exact timestamp. The log file is not strictly time-ordered, so the search sometimes fails and AdGuard
returns an empty page although older entries exist. The collector then re-locates its position
with `offset` (a linear scan, used only for this) instead of treating the page as the end.
"""
import base64
import ipaddress
import json
import logging
import re
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
RECOVERY_TRIES = 20            # offset lookups per page when AdGuard cannot seek
PERIODIC_HOURS = 18            # an unknown domain queried in this many hours of a day is machine traffic
ALWAYS_ON_HOURS = 18           # a device querying a domain in this many hours of a day is not being used for it
LAG = 120                      # seconds by which AdGuard may write an entry after newer ones
AGG_VERSION = "3"              # bump when rebuild_day changes, to re-derive all hour-level history
SERVICES_REFRESH = 24 * 3600
CLIENTS_REFRESH = 600
MAC = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$")
BLOCK_REASONS = {
    "FilteredBlackList", "FilteredSafeBrowsing", "FilteredParental",
    "FilteredInvalid", "FilteredBlockedService",
}


def parse_time(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def fingerprint(e):
    q = e.get("question") or {}
    return f"{e.get('time')}|{client_key(e)}|{q.get('name') or q.get('host')}|{q.get('type')}"


def known_clients(clients, dhcp):
    """Map client key (IP or ClientID) -> name from AdGuard's client list and DHCP leases.

    Persistent clients win over runtime ("auto") clients, which win over DHCP host names.
    Persistent clients identified by MAC are resolved to an IP through the DHCP leases.
    CIDR ranges cannot be listed and are skipped.
    """
    leases = (dhcp or {}).get("leases") or []
    leases = leases + ((dhcp or {}).get("static_leases") or [])
    mac_ip = {(l.get("mac") or "").lower(): l["ip"] for l in leases if l.get("ip")}
    out = {l["ip"]: l.get("hostname") or "" for l in leases if l.get("ip")}
    for a in (clients or {}).get("auto_clients") or []:
        if a.get("ip"):
            out[a["ip"]] = a.get("name") or out.get(a["ip"], "")
    for pc in (clients or {}).get("clients") or []:
        for cid in pc.get("ids") or []:
            cid = cid.strip().lower()
            if "/" in cid:
                continue
            if MAC.match(cid):
                cid = mac_ip.get(cid.replace("-", ":"))
                if not cid:
                    continue
            out[cid] = pc.get("name") or ""
    return out


def client_key(e):
    """A device is its ClientID (DoH/DoT/DoQ) when it sends one, else its IP."""
    return e.get("client_id") or e.get("client") or "unknown"


def norm_key(k):
    """Canonical IP (as AdGuard writes it in the query log) or ClientID; None if neither, or if the
    address cannot be a device (loopback, multicast, ... e.g. from /etc/hosts)."""
    try:
        ip = ipaddress.ip_address(k)
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            return None
        return str(ip)
    except ValueError:
        return k if re.fullmatch(r"[a-z0-9-]{1,64}", k) else None


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

    def querylog(self, older_than="", offset=None):
        params = {"older_than": older_than, "limit": PAGE_SIZE}
        if offset is not None:
            params["offset"] = offset
        return self.get("/control/querylog", params)


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

    def add_known(self, known):
        """Create rows for devices AdGuard knows about, so they can be assigned before they query."""
        known = {nk: n for k, n in known.items() if (nk := norm_key(k))}
        for key, name in known.items():
            self._client(key, name)
        self.conn.executemany("UPDATE clients SET name=? WHERE ip=?", [(n, k) for k, n in known.items() if n])
        # drop non-device addresses an earlier version imported and that never sent a query
        junk = [(cid,) for ip, cid in self.clients.items() if norm_key(ip) is None and ip != "unknown"]
        if junk:
            self.conn.executemany(
                "DELETE FROM clients WHERE id=? AND first_seen IS NULL AND person_id IS NULL AND label IS NULL", junk)
            self.clients = {ip: cid for cid, ip in self.conn.execute("SELECT id, ip FROM clients")}

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
            ip = client_key(e)
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
            "INSERT INTO hourly(hour, client_id, domain_id, queries, blocked, slots) VALUES(?,?,?,?,?,?) "
            "ON CONFLICT(hour, client_id, domain_id) DO UPDATE SET "
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


def mark_periodic(conn, start, end):
    """Mark uncategorized domains that some device queried in at least PERIODIC_HOURS distinct hours
    of [start, end) as machine traffic (IoT clouds, sync, telemetry). People do not use one site
    around the clock; devices that phone home do. Returns the number of newly marked domains."""
    ids = [r[0] for r in conn.execute(
        "SELECT DISTINCT domain_id FROM (SELECT h.client_id, h.domain_id FROM hourly h "
        "JOIN domains d ON d.id=h.domain_id WHERE d.periodic=0 AND d.category=? AND h.hour>=? AND h.hour<? "
        "GROUP BY h.client_id, h.domain_id HAVING COUNT(*)>=?)",
        (categories.OTHER, start, end, PERIODIC_HOURS))]
    conn.executemany("UPDATE domains SET periodic=1, category=? WHERE id=?", [(categories.AUTO, i) for i in ids])
    return len(ids)


def mark_idle(conn, start, end, now=None):
    """Flag the hourly rows of [start, end) whose device queried that domain in at least
    ALWAYS_ON_HOURS distinct hours of the day (of the last 24 hours while the day is still running).
    Apps left open (mail, chat, cloud drives, AI assistants) and IoT clouds keep polling all day and
    night; that is not someone using the device."""
    nxt = (int(now or time.time()) // 3600 + 1) * 3600
    w1 = min(end, nxt)
    w0 = min(start, w1 - 86400)
    conn.execute(
        "UPDATE hourly SET idle=((client_id, domain_id) IN (SELECT client_id, domain_id FROM hourly "
        "WHERE hour>=? AND hour<? GROUP BY client_id, domain_id HAVING COUNT(*)>=?)) WHERE hour>=? AND hour<?",
        (w0, w1, ALWAYS_ON_HOURS, start, end))


def rebuild_day(conn, day: int):
    """Recompute idle flags, daily, group_hourly and group_daily for one local day from hourly."""
    start, end = db.day_bounds(db.int_day(day))
    mark_idle(conn, start, end)
    conn.execute("DELETE FROM daily WHERE day=?", (day,))
    conn.execute(
        "INSERT INTO daily SELECT ?, client_id, domain_id, SUM(queries), SUM(blocked), "
        "SUM(CASE WHEN idle THEN 0 ELSE popcount(slots) END) "
        "FROM hourly WHERE hour>=? AND hour<? GROUP BY client_id, domain_id",
        (day, start, end),
    )
    rebuild_groups(conn, day, start, end)


def rebuild_groups(conn, day, start, end):
    """Each active slot of a device goes to one category: foreground before background, then the
    category with more queries in that hour. Services likewise. So per-category time adds up to the
    total instead of counting a slot once for every app that happened to query in it."""
    bg = categories.BACKGROUND
    cells = defaultdict(lambda: (defaultdict(lambda: [0, 0, False]), defaultdict(lambda: [0, 0, False])))
    for hour, cid, queries, slots, service, category in conn.execute(
        "SELECT h.hour, h.client_id, h.queries, h.slots, d.service, d.category FROM hourly h "
        "JOIN domains d ON d.id=h.domain_id WHERE h.hour>=? AND h.hour<? AND h.idle=0",
        (start, end),
    ):
        cats, svcs = cells[(hour, cid)]
        for groups, key in ((cats, category), (svcs, service)):
            if key:
                g = groups[key]
                g[0] += queries
                g[1] |= slots
                g[2] = category in bg
    acc = {}
    for (hour, cid), (cats, svcs) in cells.items():
        for kind, groups in (("c", cats), ("s", svcs)):
            taken = 0
            for key, (_, slots, is_bg) in sorted(groups.items(), key=lambda kv: (kv[1][2], -kv[1][0], kv[0])):
                if slots & ~taken:
                    acc[(hour, cid, kind, key)] = slots & ~taken
                    taken |= slots
        fg = 0
        for _, slots, is_bg in cats.values():
            if not is_bg:
                fg |= slots
        if fg:
            acc[(hour, cid, "a", "")] = fg
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
            "ingested_total": 0, "backfilling": False, "backfill_at": None, "regroup_pending": 0,
        }
        self._next_services = 0
        self._next_clients = 0
        self._next_prune = 0
        with self.lock:
            categories.replace_rules(self.conn, "builtin", categories.builtin_rules())
            self._apply_rule_change()
            if db.get_state(self.conn, "history_done") is None and db.get_state(self.conn, "floor") is None:
                # Earlier versions could stop importing history early: import what is older than
                # the oldest entry already held.
                floor = self.conn.execute("SELECT MIN(first_seen) FROM clients").fetchone()[0]
                if floor is not None:
                    db.set_state(self.conn, "floor", floor)
            if db.get_state(self.conn, "agg_version") != AGG_VERSION:
                # how time is derived changed: rebuild every day that still has hour-level data
                days = {db.local_day_of(h) for (h,) in self.conn.execute(
                    "SELECT DISTINCT hour FROM hourly")}
                db.set_state(self.conn, "dirty_days", ",".join(map(str, self._dirty() | days)))
                db.set_state(self.conn, "agg_version", AGG_VERSION)
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

    def _refresh_clients(self):
        try:
            clients = self.api.get("/control/clients")
        except Exception as ex:
            log.warning("client list unavailable: %s", ex)
            return
        try:
            dhcp = self.api.get("/control/dhcp/status")
        except Exception:  # DHCP is optional
            dhcp = None
        known = known_clients(clients, dhcp)
        with self.lock:
            self.ingester.add_known(known)
            self.conn.commit()

    # --- polling -----------------------------------------------------------

    def _dirty(self):
        v = db.get_state(self.conn, "dirty_days", "")
        return {int(x) for x in v.split(",") if x}

    def _flush_dirty(self):
        dirty = self._dirty()
        if dirty:
            now = int(time.time())
            windows = [db.day_bounds(db.int_day(d)) for d in dirty] + [(now - 86400, now)]
            if sum(mark_periodic(self.conn, a, b) for a, b in windows):
                self.schedule_regroup()  # other days still count the newly marked domains
        for d in sorted(dirty):
            rebuild_day(self.conn, d)
        db.set_state(self.conn, "dirty_days", None)
        self.conn.commit()

    def _run_state(self):
        c = self.conn
        floor = db.get_state(c, "floor")
        return {
            "top": float(db.get_state(c, "run_top")), "stop": float(db.get_state(c, "run_stop")),
            "older": db.get_state(c, "run_older", ""), "pos": float(db.get_state(c, "run_pos", "inf")),
            "seen": int(db.get_state(c, "run_seen", "0")),
            "edge": json.loads(db.get_state(c, "run_edge", "{}")),
            "recent": json.loads(db.get_state(c, "recent", "{}")),
            "history": db.get_state(c, "history_done") is None,
            "floor": float(floor) if floor is not None else None,
        }

    def _fetch(self, st):
        """Next page of the run -> (entries not yet seen in this run, next older_than).
        Returns (None, None) at the end of the log.

        The log is only roughly time-ordered, so "seen" is decided by fingerprint for entries
        within LAG of the run position (`edge`) or of the previous run's newest entry (`recent`)."""
        def fresh_of(data):
            out = []
            for e in data:
                ts = parse_time(e["time"])
                if ts <= st["top"] and ts < st["pos"] + LAG and fingerprint(e) not in st["edge"]                         and fingerprint(e) not in st["recent"]:
                    out.append((ts, e))
            return out

        page = self.api.querylog(st["older"])
        data = page.get("data") or []
        oldest = page.get("oldest") or ""
        if data:
            return fresh_of(data), oldest
        if oldest and (not st["older"] or parse_time(oldest) < parse_time(st["older"])):
            return [], oldest  # AdGuard stopped scanning early; continue from where it stopped
        # Empty page: the end of the log, or AdGuard failed to seek. Re-locate by offset.
        offset = st["seen"]
        for _ in range(RECOVERY_TRIES):
            page = self.api.querylog("", offset)
            data = page.get("data") or []
            if not data:
                return None, None
            fresh = fresh_of(data)
            if fresh:
                return fresh, page.get("oldest") or ""
            offset += len(data)  # entries newer than the run position: newer ones arrived meanwhile
            st["seen"] = offset
        raise RuntimeError("cannot locate the query log position; will retry")

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
                top = max(parse_time(e["time"]) for e in data)
                cursor = float(db.get_state(c, "cursor", "0"))
                recent = json.loads(db.get_state(c, "recent", "{}"))
                if db.get_state(c, "history_done") is not None and all(
                        parse_time(e["time"]) <= cursor - LAG or fingerprint(e) in recent for e in data):
                    return False
                db.set_state(c, "run_top", max(top, cursor))
                db.set_state(c, "run_stop", cursor - LAG)  # late-written entries can be older than the cursor
                for k in ("run_older", "run_pos", "run_seen", "run_edge", "run_recent"):
                    db.set_state(c, k, None)
                c.commit()
        more = True
        for _ in range(PAGES_PER_CHUNK):
            with self.lock:
                st = self._run_state()
            fresh, older = self._fetch(st)
            finished = fresh is None  # end of the log
            batch = []
            for ts, e in fresh or []:
                if ts > st["stop"] or (st["history"] and (st["floor"] is None or ts < st["floor"])):
                    batch.append((ts, e))
                elif not st["history"]:
                    finished = True  # reached what earlier runs ingested; finish this page first
            with self.lock:
                days = self.ingester.ingest(batch)
                db.set_state(c, "dirty_days", ",".join(map(str, self._dirty() | days)))
                recent = json.loads(db.get_state(c, "run_recent", "{}"))
                recent.update((fingerprint(e), ts) for ts, e in batch if ts > st["top"] - LAG)
                if finished:
                    recent.update(st["recent"])
                    db.set_state(c, "recent", json.dumps(
                        {k: v for k, v in recent.items() if v > st["top"] - LAG}))
                    db.set_state(c, "cursor", st["top"])
                    if fresh is None:
                        db.set_state(c, "history_done", 1)
                        db.set_state(c, "floor", None)
                    for k in ("run_top", "run_stop", "run_older", "run_pos", "run_seen", "run_edge", "run_recent"):
                        db.set_state(c, k, None)
                else:
                    db.set_state(c, "run_recent", json.dumps(recent))
                    if fresh:
                        pos = min(st["pos"], min(t for t, _ in fresh))
                        edge = {**st["edge"], **{fingerprint(e): ts for ts, e in fresh}}
                        db.set_state(c, "run_pos", pos)
                        db.set_state(c, "run_edge", json.dumps({k: v for k, v in edge.items() if v < pos + LAG}))
                    db.set_state(c, "run_older", older)
                    db.set_state(c, "run_seen", st["seen"] + len(fresh))
                c.commit()
            self.status["ingested_total"] += len(batch)
            if fresh:
                self.status["backfill_at"] = min(t for t, _ in fresh) * 1000
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
                if now >= self._next_clients:
                    self._next_clients = now + CLIENTS_REFRESH
                    self._refresh_clients()
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
