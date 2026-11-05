"""Minimal fake AdGuard Home API serving a synthetic query log, for local testing and demos.

    python tests/fake_adguard.py --days 21 --port 3999
then run the dashboard with ADGUARD_URL=http://127.0.0.1:3999
"""
import argparse
import json
import random
from bisect import bisect_left
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PERSONAS = {
    "192.168.1.10": ("anna-phone", {"instagram.com": 5, "scontent.cdninstagram.com": 4, "tiktok.com": 4, "v16.tiktokcdn.com": 3,
                                    "youtube.com": 2, "rr3.googlevideo.com": 2, "web.whatsapp.com": 2, "spotify.com": 2, "duolingo.com": 1}),
    "192.168.1.11": ("anna-laptop", {"docs.google.com": 3, "wikipedia.org": 2, "youtube.com": 3, "rr1.googlevideo.com": 2,
                                     "netflix.com": 2, "nflxvideo.net": 2, "chatgpt.com": 2, "reddit.com": 1}),
    "192.168.1.20": ("marko-pc", {"steampowered.com": 3, "steamcontent.com": 3, "twitch.tv": 4, "video-weaver.ttvnw.net": 3,
                                  "discord.com": 3, "reddit.com": 2, "youtube.com": 2, "github.com": 1}),
    "192.168.1.21": ("marko-phone", {"instagram.com": 2, "snapchat.com": 3, "x.com": 2, "twimg.com": 2, "discord.com": 1,
                                     "roblox.com": 2}),
    "192.168.1.30": ("tv", {"netflix.com": 4, "nflxvideo.net": 6, "youtube.com": 2, "disneyplus.com": 2}),
}
ACTIVE_HOURS = {"anna-phone": (7, 23), "anna-laptop": (9, 22), "marko-pc": (15, 26), "marko-phone": (8, 24), "tv": (19, 23)}
BACKGROUND = ["connectivitycheck.gstatic.com", "time.apple.com", "settings-win.data.microsoft.com", "a1234.akamaiedge.net",
              "mtalk.google.com", "api.tuyaeu.com", "dns.google"]
ADS = ["doubleclick.net", "googleads.g.doubleclick.net", "app-measurement.com", "graph.facebook.com", "tracker.example-ads.net"]
UPSTREAMS = ["https://dns.quad9.net:443/dns-query", "https://dns.cloudflare.com:443/dns-query"]


def generate(days, seed=1):
    rnd = random.Random(seed)
    end = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = end - timedelta(days=days)
    out = []

    def add(t, ip, name, host, reason="NotFilteredNotFound"):
        out.append({
            "time": t.isoformat(timespec="microseconds").replace("+00:00", "Z"), "client": ip,
            "client_info": {"name": name, "whois": {}, "disallowed": False, "disallowed_rule": ""},
            "question": {"name": host, "type": rnd.choice(["A", "A", "AAAA", "HTTPS"]), "class": "IN"},
            "reason": reason, "status": "NOERROR", "elapsedMs": f"{rnd.uniform(0.05, 40):.3f}",
            "cached": rnd.random() < 0.4, "upstream": rnd.choice(UPSTREAMS), "answer": [],
        })

    t = start
    focus = {}  # ip -> site used in the current 15-minute block, or None when idle
    while t < end:
        for ip, (name, sites) in PERSONAS.items():
            lo, hi = ACTIVE_HOURS[name]
            h = t.hour if t.hour >= lo else t.hour + 24
            weekend = t.weekday() >= 5
            if t.minute % 15 == 0:
                busy = lo <= h < hi and rnd.random() < (0.3 if weekend else 0.18)
                focus[ip] = rnd.choices(list(sites), weights=list(sites.values()))[0] if busy else None
            if focus.get(ip) and rnd.random() < 0.35:
                site = focus[ip] if rnd.random() < 0.8 else rnd.choices(list(sites), weights=list(sites.values()))[0]
                for _ in range(rnd.randint(1, 3)):
                    add(t + timedelta(seconds=rnd.randint(0, 59), microseconds=rnd.randint(0, 999999)), ip, name, site)
                if rnd.random() < 0.3:
                    add(t + timedelta(seconds=rnd.randint(0, 59)), ip, name, rnd.choice(ADS), "FilteredBlackList")
            if rnd.random() < 0.05:
                add(t + timedelta(seconds=rnd.randint(0, 59)), ip, name, rnd.choice(BACKGROUND))
        t += timedelta(minutes=1)
    out.sort(key=lambda e: e["time"], reverse=True)
    return out


SERVICES = {"blocked_services": [
    {"id": "instagram", "name": "Instagram", "group_id": "social_network", "rules": ["||instagram.com^", "||cdninstagram.com^"]},
    {"id": "tiktok", "name": "TikTok", "group_id": "social_network", "rules": ["||tiktok.com^", "||tiktokcdn.com^"]},
    {"id": "discord", "name": "Discord", "group_id": "messenger", "rules": ["||discord.com^", "||discord.gg^"]},
]}


def serve(entries, port):
    times = [e["time"] for e in entries][::-1]  # ascending, for bisect

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            u = urlparse(self.path)
            qp = parse_qs(u.query)
            if u.path == "/control/querylog":
                limit = int(qp.get("limit", ["500"])[0])
                older = qp.get("older_than", [""])[0]
                # entries are newest-first; find first index strictly older than `older`
                i = 0 if not older else len(times) - bisect_left(times, older)
                page = entries[i:i + limit]
                body = {"data": page, "oldest": page[-1]["time"] if page else ""}
            elif u.path == "/control/blocked_services/all":
                body = SERVICES
            else:
                self.send_response(404)
                self.end_headers()
                return
            raw = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=21)
    ap.add_argument("--port", type=int, default=3999)
    a = ap.parse_args()
    data = generate(a.days)
    print(f"serving {len(data)} entries on :{a.port}", flush=True)
    serve(data, a.port)
