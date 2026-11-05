import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app import categories, collector as col, config, db  # noqa: E402
import fake_adguard  # noqa: E402


class FakeAPI:
    def __init__(self, entries):
        self.entries = sorted(entries, key=lambda e: e["time"], reverse=True)
        self.fail_after = None
        self.calls = 0

    def querylog(self, older_than=""):
        self.calls += 1
        if self.fail_after is not None and self.calls > self.fail_after:
            raise ConnectionError("simulated outage")
        page = [e for e in self.entries if not older_than or e["time"] < older_than][:col.PAGE_SIZE]
        return {"data": page, "oldest": page[-1]["time"] if page else ""}

    def get(self, path):
        return fake_adguard.ROUTES[path]


def entry(t, ip, host, reason="NotFilteredNotFound"):
    return {"time": t.isoformat(timespec="microseconds").replace("+00:00", "Z"), "client": ip,
            "client_info": {"name": "dev-" + ip}, "question": {"name": host, "type": "A"},
            "reason": reason, "elapsedMs": "1.5", "cached": False, "upstream": "u1"}


@pytest.fixture
def make_collector(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_PATH", str(tmp_path / "t.db"))

    def make(entries):
        c = col.Collector()
        c.api = FakeAPI(entries)
        c._refresh_services()
        c._refresh_clients()
        return c
    return make


def totals(conn):
    return conn.execute("SELECT SUM(queries), SUM(blocked) FROM daily").fetchone()


def test_site_keys():
    conn = db.init(":memory:")
    categories.replace_rules(conn, "builtin", categories.builtin_rules())
    m = categories.Matcher(conn)
    assert m.site_key("scontent-vie1-1.cdninstagram.com.") == "cdninstagram.com"
    assert m.site_key("mail.google.com") == "mail.google.com"
    assert m.site_key("www.google.com") == "www.google.com"
    assert m.classify("mtalk.google.com")[1] == "Software & updates"
    assert m.site_key("foo.bar.co.uk") == "bar.co.uk"
    assert m.site_key("4.3.2.1.in-addr.arpa") == "in-addr.arpa"
    assert m.classify("cdninstagram.com") == ("Instagram", "Social networks")
    assert m.classify("nas")[1] == categories.LOCAL
    assert m.classify("unknown-ads.net", autoblock=True)[1] == categories.ADS


def test_slots_union_and_daily(make_collector):
    t = datetime(2026, 3, 2, 10, 0, 30, tzinfo=timezone.utc)
    ip = "10.0.0.5"
    entries = [
        entry(t, ip, "instagram.com"),
        entry(t + timedelta(seconds=20), ip, "scontent.cdninstagram.com"),  # same slot, other domain, same service
        entry(t + timedelta(minutes=7), ip, "instagram.com"),             # next slot
        entry(t + timedelta(minutes=8), ip, "doubleclick.net", "FilteredBlackList"),
    ]
    c = make_collector(entries)
    assert c.poll() is False
    conn = c.conn
    assert totals(conn) == (4, 1)
    day = db.local_day_of(int(t.timestamp()) // 3600 * 3600)
    g = dict(((k, key), v) for k, key, v in conn.execute(
        "SELECT kind, key, active FROM group_daily WHERE day=?", (day,)))
    assert g[("s", "Instagram")] == 2           # union: 2 slots, not 3
    assert g[("c", "Social networks")] == 2
    assert g[("a", "")] == 2                    # ads are background, not counted
    dom = dict(conn.execute("SELECT d.name, x.active FROM daily x JOIN domains d ON d.id=x.domain_id"))
    assert dom == {"instagram.com": 2, "cdninstagram.com": 1, "doubleclick.net": 1}


def test_incremental_polls_and_crash_safety(make_collector):
    base = datetime(2026, 3, 1, tzinfo=timezone.utc)
    entries = [entry(base + timedelta(seconds=7 * i), f"10.0.0.{i % 3}", f"site{i % 40}.com") for i in range(3000)]
    c = make_collector(entries[:2000])
    c.api.fail_after = 3          # first run dies mid-way through the pages
    with pytest.raises(ConnectionError):
        c.poll()
    c.api.fail_after = None
    while c.poll():
        pass
    assert totals(c.conn)[0] == 2000
    assert c.poll() is False      # nothing new: no double counting
    assert totals(c.conn)[0] == 2000
    c.api = FakeAPI(entries)      # 1000 newer entries arrive
    while c.poll():
        pass
    assert totals(c.conn)[0] == 3000


def test_recategorize_regroups_history(make_collector):
    t = datetime(2026, 3, 2, 12, 0, tzinfo=timezone.utc)
    c = make_collector([entry(t, "10.0.0.9", "example-game.io")])
    c.poll()
    day = db.local_day_of(int(t.timestamp()) // 3600 * 3600)
    categories.replace_rules(c.conn, "user", [("example-game.io", "My game", "Gaming")])
    c.rules_changed()
    c._regroup_some(100)
    row = c.conn.execute("SELECT key FROM group_daily WHERE day=? AND kind='c'", (day,)).fetchone()
    assert row == ("Gaming",)


def test_api_endpoints(make_collector):
    from fastapi.testclient import TestClient
    from app import api

    c = make_collector(fake_adguard.generate(10, seed=3))
    while c.poll():
        pass
    api.collector = c
    client = TestClient(api.app)
    meta = client.get("/api/meta").json()
    assert len(meta["clients"]) == len(fake_adguard.PERSONAS) + 5  # + clients known only to AdGuard
    anna = client.post("/api/persons", json={"name": "Anna", "color": "#e15759"}).json()["id"]
    for cl in meta["clients"]:
        if cl["ip"].startswith("192.168.1.1"):
            assert client.put(f"/api/clients/{cl['id']}", json={"person_id": anna}).status_code == 200
    rng = {"start": meta["first_day"], "end": meta["last_day"]}
    s = client.get("/api/summary", params=rng).json()["current"]
    assert s["queries"] > 0 and s["minutes"] > 0
    ins = client.get("/api/insights", params=rng).json()["persons"]
    assert {p["name"] for p in ins} == {"Anna", "Unassigned"}
    bd = client.get("/api/breakdown", params={**rng, "rows": "person", "cols": "service"}).json()
    assert "Instagram" in [col_["name"] for col_ in bd["cols"]]
    for split in ("none", "person", "category", "service", "site", "client"):
        r = client.get("/api/timeseries", params={**rng, "split": split, "metric": "minutes"})
        assert r.status_code == 200, r.text
    assert client.get("/api/timeseries", params={"start": meta["last_day"], "end": meta["last_day"]}).json()["bucket"] == "hour"
    tl = client.get("/api/timeline", params={"day": meta["last_day"], "split": "category"}).json()
    assert tl["rows"] and tl["rows"][0]["intervals"]
    heat = client.get("/api/heatmap", params={**rng, "persons": anna}).json()
    assert len(heat["values"]) == 7 and any(any(r) for r in heat["values"])
    soc = client.get("/api/top", params={**rng, "by": "person", "categories": "Social networks"}).json()
    assert soc["rows"][0]["minutes"] > 0
    assert client.get("/api/sites", params={**rng, "q": "netflix"}).json()["total"] >= 1
    assert client.get("/api/dns", params=rng).json()["reasons"]
    assert client.post("/api/rules", json={"pattern": "*.Netflix.com", "category": "Video & streaming", "service": "Netflix"}).json()["pattern"] == "netflix.com"
    assert client.post("/api/rules", json={"pattern": "bad pattern", "category": "x"}).status_code == 400
    assert client.post("/api/persons", json={"name": "Anna"}).status_code == 409


def test_known_clients_and_client_ids(make_collector):
    t = datetime(2024, 5, 6, 12, 0, tzinfo=timezone.utc)
    doh = entry(t, "203.0.113.9", "example.net") | {"client_id": "anna-doh"}
    c = make_collector([doh, entry(t, "192.168.1.10", "example.net")])
    while c.poll():
        pass
    rows = dict(c.conn.execute("SELECT ip, name FROM clients"))
    assert rows["192.168.1.40"] == "Living-room printer"        # persistent client, never queried
    assert rows["192.168.1.42"] == "Guest tablet"               # persistent by MAC, resolved via DHCP lease
    assert rows["192.168.1.43"] == "doorbell"                   # static DHCP lease
    assert rows["192.168.1.41"] == "nas.lan"                    # runtime client
    assert "10.0.0.0/24" not in rows and "203.0.113.9" not in rows
    seen = c.conn.execute("SELECT ip FROM clients WHERE last_seen IS NOT NULL ORDER BY ip").fetchall()
    assert seen == [("192.168.1.10",), ("anna-doh",)]           # DoH queries counted under the ClientID
