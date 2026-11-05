"""HTTP API + static dashboard."""
import base64
import logging
import re
import secrets
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta
from pathlib import Path
from statistics import mean, pstdev
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import categories, config, db
from .collector import Collector

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
WEB_DIR = Path(__file__).resolve().parent.parent / "web"
SM = db.SLOT_MINUTES
collector: Optional[Collector] = None


@asynccontextmanager
async def lifespan(_app):
    global collector
    if not config.DASHBOARD_PASSWORD:
        logging.getLogger("api").warning("DASHBOARD_PASSWORD is empty: anyone who can reach the port sees the stats")
    collector = Collector()
    collector.start()
    yield


app = FastAPI(title="AdGuard Stats", lifespan=lifespan)


@app.middleware("http")
async def basic_auth(request, call_next):
    if config.DASHBOARD_PASSWORD and request.url.path != "/healthz":
        ok = False
        header = request.headers.get("authorization", "")
        if header.startswith("Basic "):
            try:
                user, _, pw = base64.b64decode(header[6:]).decode().partition(":")
                ok = secrets.compare_digest(user, config.DASHBOARD_USER) & secrets.compare_digest(
                    pw, config.DASHBOARD_PASSWORD)
            except (ValueError, UnicodeDecodeError):
                ok = False
        if not ok:
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="AdGuard Stats"'})
    return await call_next(request)


def get_conn():
    conn = db.connect()
    try:
        yield conn
    finally:
        conn.close()


# --- filters ----------------------------------------------------------------

@dataclass
class F:
    start: date
    end: date
    clients: Optional[list]
    categories: list
    services: list
    sites: list
    q: str
    hide_bg: bool

    @property
    def d0(self):
        return db.day_int(self.start)

    @property
    def d1(self):
        return db.day_int(self.end)

    @property
    def t0(self):
        return db.day_bounds(self.start)[0]

    @property
    def t1(self):
        return db.day_bounds(self.end)[1]

    @property
    def days(self):
        return (self.end - self.start).days + 1

    def shifted(self, days):
        return replace(self, start=self.start - timedelta(days=days), end=self.end - timedelta(days=days))


def parse_date(s, default):
    if not s:
        return default
    try:
        return date.fromisoformat(s)
    except ValueError:
        raise HTTPException(400, f"bad date {s!r}")


def filters(
    start: Optional[str] = None, end: Optional[str] = None,
    persons: list[int] = Query(default=[]), clients: list[int] = Query(default=[]),
    categories_: list[str] = Query(default=[], alias="categories"),
    services: list[str] = Query(default=[]), sites: list[str] = Query(default=[]),
    q: str = "", hide_bg: bool = True, conn=Depends(get_conn),
) -> F:
    today = datetime.now(config.TZ).date()
    e = parse_date(end, today)
    s = parse_date(start, e - timedelta(days=6))
    if s > e:
        s, e = e, s
    ids = None
    if persons or clients:
        ids = set(clients)
        if persons:
            named = [p for p in persons if p]
            if named:
                ids |= {r[0] for r in conn.execute(
                    f"SELECT id FROM clients WHERE person_id IN ({qs(named)})", named)}
            if 0 in persons:
                ids |= {r[0] for r in conn.execute("SELECT id FROM clients WHERE person_id IS NULL")}
        ids = sorted(ids)
    return F(s, e, ids, categories_, services, sites, q.strip().lower(), hide_bg)


def qs(items):
    return ",".join("?" * len(items))


def in_clause(col, items):
    if not items:
        return "0", []
    return f"{col} IN ({qs(items)})", list(items)


BG = sorted(categories.BACKGROUND)
DOMAIN_SPLIT = {
    "none": "''", "person": "COALESCE(c.person_id, 0)", "client": "x.client_id",
    "category": "d.category", "service": "COALESCE(d.service, d.name)", "site": "d.name",
}


def minute_source(f, splits):
    if f.sites or f.q or "site" in splits:
        return "domain"
    if f.services or "service" in splits:
        return "s"
    if f.categories or "category" in splits:
        return "c"
    return "a"


def domain_conds(f):
    conds, params = [], []
    if f.categories:
        c, p = in_clause("d.category", f.categories)
        conds.append(c), params.extend(p)
    if f.services:
        c, p = in_clause("d.service", f.services)
        conds.append(c), params.extend(p)
    if f.sites:
        c, p = in_clause("d.name", f.sites)
        conds.append(c), params.extend(p)
    if f.q:
        conds.append("d.name LIKE ?")
        params.append(f"%{f.q}%")
    if f.hide_bg and not conds:
        conds.append(f"d.category NOT IN ({qs(BG)})")
        params.extend(BG)
    return conds, params


def group_conds(f, kind):
    conds, params = ["x.kind=?"], [kind]
    if kind == "c":
        if f.categories:
            c, p = in_clause("x.key", f.categories)
            conds.append(c), params.extend(p)
        elif f.hide_bg:
            conds.append(f"x.key NOT IN ({qs(BG)})")
            params.extend(BG)
    elif kind == "s":
        if f.services:
            c, p = in_clause("x.key", f.services)
            conds.append(c), params.extend(p)
        if f.categories:
            conds.append(f"x.key IN (SELECT service FROM domains WHERE service IS NOT NULL AND category IN ({qs(f.categories)}))")
            params.extend(f.categories)
        elif f.hide_bg and not f.services:
            conds.append(f"x.key NOT IN (SELECT service FROM domains WHERE service IS NOT NULL AND category IN ({qs(BG)}))")
            params.extend(BG)
    return conds, params


def source(f, metric, splits, hourly, value=None):
    """-> (sql_from_where, key_exprs, value_expr, params) for an aggregate over the filter."""
    if metric == "blocked":  # blocked traffic is mostly ads/trackers, i.e. "background": never hide it
        f = replace(f, hide_bg=False)
    src = minute_source(f, splits) if metric == "minutes" else "domain"
    if src == "domain":
        table = "hourly" if hourly else "daily"
        joins = "JOIN domains d ON d.id=x.domain_id JOIN clients c ON c.id=x.client_id"
        keys = [DOMAIN_SPLIT[s] for s in splits]
        conds, params = domain_conds(f)
        val = {"queries": "SUM(x.queries)", "blocked": "SUM(x.blocked)",
               "minutes": "SUM(popcount(x.slots))" if hourly else "SUM(x.active)"}[metric]
    else:
        table = "group_hourly" if hourly else "group_daily"
        joins = "JOIN clients c ON c.id=x.client_id"
        gsplit = dict(DOMAIN_SPLIT, category="x.key", service="x.key")
        keys = [gsplit[s] for s in splits]
        conds, params = group_conds(f, src)
        val = "SUM(popcount(x.slots))" if hourly else "SUM(x.active)"
    if hourly:
        conds.insert(0, "x.hour>=? AND x.hour<?")
        params[:0] = [f.t0, f.t1]
    else:
        conds.insert(0, "x.day BETWEEN ? AND ?")
        params[:0] = [f.d0, f.d1]
    if f.clients is not None:
        c, p = in_clause("x.client_id", f.clients)
        conds.append(c), params.extend(p)
    return f"FROM {table} x {joins} WHERE {' AND '.join(conds)}", keys, value or val, params


def agg(conn, f, metric, splits=(), bucket=None):
    """Rows of (*split_keys, bucket, value). bucket: None | 'day' | 'hour'. Minutes are real minutes."""
    if (metric == "minutes" and "client" not in splits and minute_source(f, splits) != "domain"
            and f.start >= hourly_since()):
        return agg_per_person(conn, f, splits, bucket)
    hourly = bucket == "hour"
    frm, keys, val, params = source(f, metric, splits, hourly)
    b = {"hour": "x.hour", "day": "x.day"}.get(bucket, "NULL")
    group = [f"k{i}" for i in range(len(keys))] + (["b"] if bucket else [])
    sel = ", ".join([f"{k} AS k{i}" for i, k in enumerate(keys)] + [f"{b} AS b", f"{val} AS v"])
    sql = f"SELECT {sel} {frm}" + (f" GROUP BY {', '.join(group)}" if group else "")
    rows = conn.execute(sql, params).fetchall()
    mult = SM if metric == "minutes" else 1
    return [(*r[:-1], (r[-1] or 0) * mult) for r in rows]


def agg_per_person(conn, f, splits, bucket):
    """Like agg() for minutes, but a person's devices active in the same 5-minute slot count once.
    Unassigned devices count separately. Needs hour-level data (slot masks)."""
    frm, keys, _, params = source(f, "minutes", splits, True)
    unit = "CASE WHEN c.person_id IS NULL THEN -x.client_id ELSE c.person_id END"
    sel = [f"{k} AS k{i}" for i, k in enumerate(keys)] + ["x.hour AS h", f"{unit} AS u", "popcount(bitor(x.slots))"]
    group = [f"k{i}" for i in range(len(keys))] + ["h", "u"]
    out, day_of = Counter(), {}
    for *k, h, _, v in conn.execute(f"SELECT {', '.join(sel)} {frm} GROUP BY {', '.join(group)}", params):
        if bucket == "hour":
            b = h
        elif bucket == "day":
            b = day_of.get(h) or day_of.setdefault(h, db.local_day_of(h))
        else:
            b = None
        out[(*k, b)] += v
    return [(*k, v * SM) for k, v in out.items()]


def hourly_since():
    return datetime.now(config.TZ).date() - timedelta(days=config.HOURLY_RETENTION_DAYS - 1)


# --- lookups ----------------------------------------------------------------

def names(conn):
    persons = {pid: n for pid, n in conn.execute("SELECT id, name FROM persons")}
    persons[0] = "Unassigned"
    clients = {cid: (lbl or nm or ip) for cid, ip, nm, lbl in conn.execute("SELECT id, ip, name, label FROM clients")}
    return {"person": persons, "client": clients}


def label(lookup, split, key):
    if split in lookup:
        return lookup[split].get(key, str(key))
    return key if key != "" else "All"


# --- endpoints: data ---------------------------------------------------------

def bucket_for(f, requested):
    if requested and requested != "auto":
        if requested == "hour" and f.days > 31:
            return "day"
        return requested
    if f.days <= 3:
        return "hour"
    if f.days <= 120:
        return "day"
    if f.days <= 730:
        return "week"
    return "month"


def rebucket_day(day_int, bucket):
    d = db.int_day(day_int)
    if bucket == "week":
        d -= timedelta(days=d.weekday())
    elif bucket == "month":
        d = d.replace(day=1)
    return d.isoformat()


def bucket_labels(f, bucket):
    if bucket == "hour":
        return list(range(f.t0 - f.t0 % 3600, f.t1, 3600))
    out, d = [], f.start
    while d <= f.end:
        lbl = rebucket_day(db.day_int(d), bucket)
        if not out or out[-1] != lbl:
            out.append(lbl)
        d += timedelta(days=1)
    return out


@app.get("/api/timeseries")
def timeseries(metric: str = "minutes", split: str = "none", bucket: str = "auto", top: int = 8,
               f: F = Depends(filters), conn=Depends(get_conn)):
    check_metric(metric), check_split(split)
    bk = bucket_for(f, bucket)
    rows = agg(conn, f, metric, [split] if split != "none" else [], "hour" if bk == "hour" else "day")
    series = defaultdict(Counter)
    for *k, b, v in rows:
        key = k[0] if k else ""
        series[key][b if bk == "hour" else rebucket_day(b, bk)] += v
    totals = sorted(series, key=lambda k: -sum(series[k].values()))
    if len(totals) > top:
        other = Counter()
        for k in totals[top:]:
            other.update(series.pop(k))
        totals = totals[:top]
        series["__other__"] = other
        totals.append("__other__")
    lookup = names(conn)
    labels = bucket_labels(f, bk)
    return {
        "bucket": bk, "metric": metric,
        "labels": [ts * 1000 for ts in labels] if bk == "hour" else labels,
        "series": [{"key": k, "name": "Other" if k == "__other__" else label(lookup, split, k),
                    "data": [series[k].get(b, 0) for b in labels]} for k in totals],
    }


@app.get("/api/top")
def top(by: str = "site", sort: str = "minutes", limit: int = 20, f: F = Depends(filters), conn=Depends(get_conn)):
    check_split(by)
    if by == "none":
        raise HTTPException(400, "by must not be none")
    rows = defaultdict(lambda: {"queries": 0, "blocked": 0, "minutes": 0})
    for metric in ("queries", "blocked", "minutes"):
        for k, _, v in agg(conn, f, metric, [by]):
            rows[k][metric] = v
    lookup = names(conn)
    extra = {}
    if by in ("site", "service"):
        col = "name" if by == "site" else "service"
        for k, cat, svc in conn.execute(f"SELECT {col}, category, service FROM domains WHERE {col} IS NOT NULL"):
            extra.setdefault(k, {"category": cat, "service": svc})
    out = [{"key": k, "name": label(lookup, by, k), **v, **extra.get(k, {})} for k, v in rows.items()]
    key = sort if sort in ("queries", "blocked", "minutes") else "minutes"
    out.sort(key=lambda r: (-r[key], -r["queries"]))
    return {"rows": out[:max(1, min(limit, 500))], "total": len(out)}


@app.get("/api/breakdown")
def breakdown(rows: str = "person", cols: str = "category", metric: str = "minutes", limit: int = 12,
              f: F = Depends(filters), conn=Depends(get_conn)):
    check_metric(metric), check_split(rows), check_split(cols)
    data = agg(conn, f, metric, [rows, cols])
    lookup = names(conn)
    col_tot, row_tot = Counter(), Counter()
    cell = {}
    for r, c, _, v in data:
        cell[(r, c)] = v
        col_tot[c] += v
        row_tot[r] += v
    ckeys = [c for c, _ in col_tot.most_common(limit)]
    rkeys = [r for r, _ in row_tot.most_common()]
    return {
        "rows": [{"key": r, "name": label(lookup, rows, r), "total": row_tot[r]} for r in rkeys],
        "cols": [{"key": c, "name": label(lookup, cols, c)} for c in ckeys],
        "values": [[cell.get((r, c), 0) for c in ckeys] for r in rkeys],
    }


@app.get("/api/heatmap")
def heatmap(metric: str = "minutes", f: F = Depends(filters), conn=Depends(get_conn)):
    """Average per weekday (Mon=0) x local hour."""
    check_metric(metric)
    since = hourly_since()
    clipped = f.start < since
    if clipped:
        f.start = min(since, f.end)
    sums = [[0.0] * 24 for _ in range(7)]
    occ = [[0] * 24 for _ in range(7)]
    for ts in range(f.t0, f.t1, 3600):
        lt = datetime.fromtimestamp(ts, config.TZ)
        occ[lt.weekday()][lt.hour] += 1
    for _, ts, v in agg(conn, f, metric, ["none"], "hour"):
        lt = datetime.fromtimestamp(ts, config.TZ)
        sums[lt.weekday()][lt.hour] += v
    return {"values": [[round(sums[w][h] / occ[w][h], 2) if occ[w][h] else 0 for h in range(24)] for w in range(7)],
            "clipped_to": f.start.isoformat() if clipped else None}


@app.get("/api/timeline")
def timeline(day: Optional[str] = None, split: str = "category", top: int = 12,
             f: F = Depends(filters), conn=Depends(get_conn)):
    """Active 5-minute slots of one day merged into intervals, per split key."""
    check_split(split)
    d = parse_date(day, f.end)
    f.start = f.end = d
    frm, keys, val, params = source(f, "minutes", [split] if split != "none" else [], True, value="x.slots")
    key = keys[0] if keys else "''"
    acc = defaultdict(int)
    for k, hour, slots in conn.execute(f"SELECT {key}, x.hour, {val} {frm}", params):
        acc[(k, hour)] |= slots
    per_key = defaultdict(list)
    for (k, hour), slots in acc.items():
        for i in range(12):
            if slots >> i & 1:
                per_key[k].append(hour + i * db.SLOT_SECONDS)
    lookup = names(conn)
    out = []
    for k, starts in per_key.items():
        starts.sort()
        iv = []
        for s in starts:
            if iv and iv[-1][1] == s:
                iv[-1][1] = s + db.SLOT_SECONDS
            else:
                iv.append([s, s + db.SLOT_SECONDS])
        out.append({"key": k, "name": label(lookup, split, k), "minutes": len(starts) * SM,
                    "intervals": [[a * 1000, b * 1000] for a, b in iv]})
    out.sort(key=lambda r: -r["minutes"])
    t0, t1 = db.day_bounds(d)
    return {"day": d.isoformat(), "start": t0 * 1000, "end": t1 * 1000, "rows": out[:top],
            "available": d >= hourly_since()}


def summary_values(conn, f):
    frm, _, _, params = source(f, "queries", [], False)
    queries, sites, devices = conn.execute(
        f"SELECT SUM(x.queries), COUNT(DISTINCT x.domain_id), COUNT(DISTINCT x.client_id) {frm}", params).fetchone()
    frm, _, _, params = source(f, "blocked", [], False)
    all_queries, blocked = conn.execute(f"SELECT SUM(x.queries), SUM(x.blocked) {frm}", params).fetchone()
    minutes = sum(r[-1] for r in agg(conn, f, "minutes"))
    conds, p = domain_conds(f)
    where = " AND ".join(["d.first_seen>=? AND d.first_seen<?"] + conds)
    new_params = [f.t0, f.t1] + p
    if f.clients is not None:
        c, cp = in_clause("d.first_client", f.clients)
        where += " AND " + c
        new_params += cp
    new_sites = conn.execute(f"SELECT COUNT(*) FROM domains d WHERE {where}", new_params).fetchone()[0]
    mc = "day BETWEEN ? AND ? AND kind='perf'"
    mp = [f.d0, f.d1]
    if f.clients is not None:
        c, cp = in_clause("client_id", f.clients)
        mc += " AND " + c
        mp += cp
    perf = dict(conn.execute(f"SELECT key, SUM(value) FROM meta_daily WHERE {mc} GROUP BY key", mp).fetchall())
    timed = perf.get("timed") or 0
    all_q = conn.execute(f"SELECT SUM(value) FROM meta_daily WHERE {mc.replace('perf', 'qtype')}", mp).fetchone()[0] or 0
    return {
        "queries": queries or 0, "blocked": blocked or 0, "minutes": minutes,
        "block_rate": round(blocked / all_queries, 4) if all_queries else None,
        "minutes_per_day": round(minutes / f.days, 1), "sites": sites or 0, "devices": devices or 0,
        "new_sites": new_sites,
        "latency_ms": round(perf.get("elapsed_us", 0) / timed / 1000, 2) if timed else None,
        "cache_rate": round((perf.get("cached") or 0) / all_q, 4) if all_q else None,
    }


@app.get("/api/summary")
def summary(f: F = Depends(filters), conn=Depends(get_conn)):
    return {"days": f.days, "current": summary_values(conn, f), "previous": summary_values(conn, f.shifted(f.days))}


@app.get("/api/sites")
def sites(sort: str = "queries", limit: int = 100, offset: int = 0, f: F = Depends(filters), conn=Depends(get_conn)):
    order = {"queries": "q DESC", "blocked": "b DESC", "minutes": "m DESC", "devices": "n DESC",
             "name": "d.name", "first_seen": "d.first_seen DESC"}.get(sort, "q DESC")
    frm, _, _, params = source(f, "queries", [], False)
    total = conn.execute(f"SELECT COUNT(DISTINCT x.domain_id) {frm}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT d.id, d.name, d.category, d.service, d.first_seen, SUM(x.queries) q, SUM(x.blocked) b, "
        f"SUM(x.active) m, COUNT(DISTINCT x.client_id) n {frm} GROUP BY d.id ORDER BY {order} LIMIT ? OFFSET ?",
        params + [max(1, min(limit, 1000)), max(0, offset)]).fetchall()
    return {"total": total, "rows": [
        {"id": r[0], "name": r[1], "category": r[2], "service": r[3], "first_seen": r[4] and r[4] * 1000,
         "queries": r[5], "blocked": r[6], "minutes": r[7] * SM, "devices": r[8]} for r in rows]}


@app.get("/api/new_sites")
def new_sites(limit: int = 100, f: F = Depends(filters), conn=Depends(get_conn)):
    conds, p = domain_conds(f)
    where = " AND ".join(["d.first_seen>=? AND d.first_seen<?"] + conds)
    params = [f.t0, f.t1] + p
    if f.clients is not None:
        c, cp = in_clause("d.first_client", f.clients)
        where += " AND " + c
        params += cp
    rows = conn.execute(
        f"SELECT d.name, d.category, d.service, d.first_seen, d.first_client, "
        f"(SELECT SUM(queries) FROM daily WHERE domain_id=d.id) FROM domains d WHERE {where} "
        f"ORDER BY d.first_seen DESC LIMIT ?", params + [max(1, min(limit, 1000))]).fetchall()
    lookup = names(conn)["client"]
    return {"rows": [{"name": r[0], "category": r[1], "service": r[2], "first_seen": r[3] * 1000,
                      "client": lookup.get(r[4], "?"), "queries": r[5] or 0} for r in rows]}


@app.get("/api/insights")
def insights(f: F = Depends(filters), conn=Depends(get_conn)):
    """Per-person behaviour summary: averages, weekday/weekend, late night, spikes, top interests."""
    lookup = names(conn)
    per_day = defaultdict(Counter)
    for p, day, v in agg(conn, f, "minutes", ["person"], "day"):
        per_day[p][day] += v
    q_tot, b_tot = Counter(), Counter()
    for p, _, v in agg(conn, replace(f, hide_bg=False), "queries", ["person"]):
        q_tot[p] = v
    for p, _, v in agg(conn, f, "blocked", ["person"]):
        b_tot[p] = v
    top_cat = defaultdict(Counter)
    for p, c, _, v in agg(conn, f, "minutes", ["person", "category"]):
        top_cat[p][c] = v
    top_svc = defaultdict(Counter)
    for p, s, _, v in agg(conn, f, "minutes", ["person", "service"]):
        top_svc[p][s] = v
    hf = replace(f, start=max(f.start, hourly_since()))
    night, hours = Counter(), defaultdict(Counter)
    if hf.start <= hf.end:
        for p, ts, v in agg(conn, hf, "minutes", ["person"], "hour"):
            h = datetime.fromtimestamp(ts, config.TZ).hour
            hours[p][h] += v
            if h < 5:
                night[p] += v
    all_days = [db.day_int(f.start + timedelta(days=i)) for i in range(f.days)]
    out = []
    for p in set(per_day) | set(q_tot):
        series = [per_day[p].get(d, 0) for d in all_days]
        wk = [v for d, v in zip(all_days, series) if db.int_day(d).weekday() < 5]
        we = [v for d, v in zip(all_days, series) if db.int_day(d).weekday() >= 5]
        mu, sd = mean(series), pstdev(series)
        spikes = [{"day": db.int_day(d).isoformat(), "minutes": v} for d, v in zip(all_days, series)
                  if len(series) >= 7 and v > mu + 2 * sd and v >= 60]
        out.append({
            "person": p, "name": label(lookup, "person", p), "minutes": sum(series),
            "avg_per_day": round(mu, 1), "weekday_avg": round(mean(wk), 1) if wk else None,
            "weekend_avg": round(mean(we), 1) if we else None, "night_minutes": night[p],
            "peak_hour": hours[p].most_common(1)[0][0] if hours[p] else None,
            "queries": q_tot[p], "block_rate": round(b_tot[p] / q_tot[p], 4) if q_tot[p] else 0,
            "top_categories": [{"name": k, "minutes": v} for k, v in top_cat[p].most_common(5)],
            "top_services": [{"name": k, "minutes": v} for k, v in top_svc[p].most_common(5)],
            "spikes": spikes,
        })
    out.sort(key=lambda r: -r["minutes"])
    return {"persons": out}


@app.get("/api/dns")
def dns_stats(f: F = Depends(filters), conn=Depends(get_conn)):
    """Resolver-side metrics from meta_daily: reasons, query types, upstreams, latency and cache per day."""
    cond, params = "day BETWEEN ? AND ?", [f.d0, f.d1]
    if f.clients is not None:
        c, p = in_clause("client_id", f.clients)
        cond += " AND " + c
        params += p
    dist = defaultdict(Counter)
    per_day = defaultdict(Counter)
    for day, kind, key, v in conn.execute(
            f"SELECT day, kind, key, SUM(value) FROM meta_daily WHERE {cond} GROUP BY day, kind, key", params):
        if kind == "perf":
            per_day[day][key] += v
        else:
            dist[kind][key] += v
            if kind == "reason":
                per_day[day]["queries"] += v
                if key.startswith("Filtered") and key not in ("FilteredSafeSearch",):
                    per_day[day]["blocked"] += v
    days = [db.day_int(f.start + timedelta(days=i)) for i in range(f.days)]
    return {
        "reasons": dist["reason"].most_common(), "qtypes": dist["qtype"].most_common(15),
        "upstreams": dist["upstream"].most_common(10),
        "days": [db.int_day(d).isoformat() for d in days],
        "latency_ms": [round(per_day[d]["elapsed_us"] / per_day[d]["timed"] / 1000, 2) if per_day[d]["timed"] else None for d in days],
        "cache_rate": [round(per_day[d]["cached"] / per_day[d]["queries"], 4) if per_day[d]["queries"] else None for d in days],
        "block_rate": [round(per_day[d]["blocked"] / per_day[d]["queries"], 4) if per_day[d]["queries"] else None for d in days],
    }


def check_metric(m):
    if m not in ("queries", "blocked", "minutes"):
        raise HTTPException(400, "metric must be queries, blocked or minutes")


def check_split(s):
    if s not in DOMAIN_SPLIT:
        raise HTTPException(400, f"split must be one of {', '.join(DOMAIN_SPLIT)}")


# --- endpoints: configuration ------------------------------------------------

@app.get("/api/meta")
def meta(conn=Depends(get_conn)):
    persons = [{"id": i, "name": n, "color": c} for i, n, c in conn.execute("SELECT id, name, color FROM persons ORDER BY name")]
    clients = [{"id": i, "ip": ip, "name": n, "label": lb, "person_id": p,
                "first_seen": fs and fs * 1000, "last_seen": ls and ls * 1000}
               for i, ip, n, lb, p, fs, ls in conn.execute(
                   "SELECT id, ip, name, label, person_id, first_seen, last_seen FROM clients ORDER BY ip")]
    cats = {c for (c,) in conn.execute("SELECT DISTINCT category FROM rules")} | \
           {c for (c,) in conn.execute("SELECT DISTINCT category FROM domains")} | {categories.OTHER}
    services = [s for (s,) in conn.execute("SELECT DISTINCT service FROM domains WHERE service IS NOT NULL ORDER BY service")]
    lo, hi = conn.execute("SELECT MIN(day), MAX(day) FROM daily").fetchone()
    return {
        "persons": persons, "clients": clients, "categories": sorted(cats), "background": BG,
        "services": services,
        "first_day": lo and db.int_day(lo).isoformat(), "last_day": hi and db.int_day(hi).isoformat(),
        "hourly_since": hourly_since().isoformat(), "slot_minutes": SM, "timezone": str(config.TZ),
        "today": datetime.now(config.TZ).date().isoformat(),
        "collector": collector.status if collector else None, "adguard_url": config.ADGUARD_URL,
        "auth": bool(config.DASHBOARD_PASSWORD),
    }


class PersonIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    color: Optional[str] = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")


class ClientIn(BaseModel):
    label: Optional[str] = Field(default=None, max_length=64)
    person_id: Optional[int] = None


class RuleIn(BaseModel):
    pattern: str = Field(min_length=1, max_length=253)
    category: str = Field(min_length=1, max_length=64)
    service: Optional[str] = Field(default=None, max_length=64)


DOMAIN_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$")


def write(conn, sql, params):
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur
    except db.sqlite3.IntegrityError as ex:
        raise HTTPException(409, str(ex))


@app.post("/api/persons")
def add_person(p: PersonIn, conn=Depends(get_conn)):
    cur = write(conn, "INSERT INTO persons(name, color) VALUES(?, ?)", (p.name.strip(), p.color))
    return {"id": cur.lastrowid}


@app.put("/api/persons/{pid}")
def edit_person(pid: int, p: PersonIn, conn=Depends(get_conn)):
    if not write(conn, "UPDATE persons SET name=?, color=? WHERE id=?", (p.name.strip(), p.color, pid)).rowcount:
        raise HTTPException(404)
    return {"ok": True}


@app.delete("/api/persons/{pid}")
def delete_person(pid: int, conn=Depends(get_conn)):
    write(conn, "DELETE FROM persons WHERE id=?", (pid,))
    return {"ok": True}


@app.put("/api/clients/{cid}")
def edit_client(cid: int, c: ClientIn, conn=Depends(get_conn)):
    lbl = (c.label or "").strip() or None
    if not write(conn, "UPDATE clients SET label=?, person_id=? WHERE id=?", (lbl, c.person_id or None, cid)).rowcount:
        raise HTTPException(404)
    return {"ok": True}


@app.get("/api/rules")
def list_rules(conn=Depends(get_conn)):
    rows = conn.execute("SELECT pattern, category, service FROM rules WHERE source='user' ORDER BY pattern").fetchall()
    counts = Counter(s for (s,) in conn.execute("SELECT source FROM rules"))
    return {"rules": [{"pattern": p, "category": c, "service": s} for p, c, s in rows], "counts": counts,
            "regroup_pending": collector.status["regroup_pending"] if collector else 0}


@app.post("/api/rules")
def add_rule(r: RuleIn, conn=Depends(get_conn)):
    pattern = categories.normalize(r.pattern).lstrip("*.")
    if not DOMAIN_RE.match(pattern):
        raise HTTPException(400, "pattern must be a domain suffix such as example.com")
    write(conn, "INSERT OR REPLACE INTO rules(pattern, source, service, category) VALUES(?, 'user', ?, ?)",
          (pattern, (r.service or "").strip() or None, r.category.strip()))
    collector.rules_changed()
    return {"ok": True, "pattern": pattern}


@app.delete("/api/rules/{pattern}")
def delete_rule(pattern: str, conn=Depends(get_conn)):
    write(conn, "DELETE FROM rules WHERE source='user' AND pattern=?", (pattern,))
    collector.rules_changed()
    return {"ok": True}


@app.get("/healthz")
def healthz():
    return {"ok": True, "collector": collector.status if collector else None}


app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
