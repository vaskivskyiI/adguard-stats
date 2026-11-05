"""Domain -> site key / service / category.

Rules are domain suffixes from three sources, merged in the `rules` table:
  user     - edited in the dashboard, always wins on equal suffix length
  builtin  - app/data/categories.json
  adguard  - AdGuard Home "blocked services" catalogue (service names + groups)
The longest matching suffix wins; on equal length the source priority above decides.
"""
import json
from pathlib import Path

import tldextract

BUILTIN_FILE = Path(__file__).parent / "data" / "categories.json"
SOURCE_PRIORITY = {"user": 0, "builtin": 1, "adguard": 2}

OTHER = "Other"
ADS = "Ads & tracking"
LOCAL = "Local network"
# Traffic devices generate on their own; excluded from "active time" and hidden by the dashboard's
# "hide background" switch.
BACKGROUND = {ADS, "Infrastructure", "Software & updates", "Smart home & IoT", LOCAL}

ADGUARD_GROUPS = {
    "social_network": "Social networks",
    "messenger": "Messaging",
    "streaming": "Video & streaming",
    "gaming": "Gaming",
    "shopping": "Shopping",
    "dating": "Dating",
    "gambling": "Gambling",
    "ai": "AI tools",
    "software": "Software & updates",
    "cdn": "Infrastructure",
    "hosting": "Infrastructure",
    "privacy": "Privacy & VPN",
}

_extract = tldextract.TLDExtract(suffix_list_urls=())  # bundled public suffix list, no network


def normalize(name: str) -> str:
    return (name or "").strip().rstrip(".").lower()


def builtin_rules():
    data = json.loads(BUILTIN_FILE.read_text(encoding="utf-8"))
    out = []
    for category, services in data.items():
        if category.startswith("_"):
            continue
        for service, patterns in services.items():
            for p in patterns:
                out.append((normalize(p), None if service == "_" else service, category))
    return out


def adguard_rules(payload):
    """Rules from GET /control/blocked_services/all. Rules look like '||facebook.com^'."""
    out = []
    for svc in payload.get("blocked_services") or []:
        category = ADGUARD_GROUPS.get(svc.get("group_id") or "", OTHER)
        for rule in svc.get("rules") or []:
            r = rule.strip()
            if not r.startswith("||") or not r.endswith("^"):
                continue
            pattern = normalize(r[2:-1])
            if pattern and "*" not in pattern and "/" not in pattern:
                out.append((pattern, svc.get("name") or svc.get("id"), category))
    return out


def replace_rules(conn, source, rules):
    conn.execute("DELETE FROM rules WHERE source=?", (source,))
    conn.executemany(
        "INSERT OR REPLACE INTO rules(pattern, source, service, category) VALUES(?,?,?,?)",
        [(p, source, s, c) for p, s, c in rules],
    )


class Matcher:
    def __init__(self, conn):
        self.rules = {}
        for pattern, source, service, category in conn.execute(
            "SELECT pattern, source, service, category FROM rules"
        ):
            cur = self.rules.get(pattern)
            if cur is None or SOURCE_PRIORITY[source] < SOURCE_PRIORITY[cur[0]]:
                self.rules[pattern] = (source, service, category)

    def _lookup(self, name):
        labels = name.split(".")
        for i in range(len(labels)):
            suffix = ".".join(labels[i:])
            hit = self.rules.get(suffix)
            if hit:
                return suffix, hit
        return None, None

    def site_key(self, fqdn):
        """Aggregation key: the registrable domain, or a more specific rule pattern if one matches
        (e.g. mail.google.com stays separate from google.com)."""
        name = normalize(fqdn)
        if name.endswith(".arpa"):
            return "in-addr.arpa" if name.endswith("in-addr.arpa") else "ip6.arpa"
        base = _extract(name).registered_domain or name
        pattern, _ = self._lookup(name)
        if pattern and len(pattern) > len(base) and name.endswith(pattern):
            return pattern
        return base

    def classify(self, site, autoblock=False):
        """-> (service, category) for a site key."""
        _, hit = self._lookup(site)
        if hit:
            return hit[1], hit[2]
        if site.endswith(".arpa") or "." not in site or not _extract(site).suffix:
            return None, LOCAL
        return None, ADS if autoblock else OTHER


def recategorize_domains(conn):
    """Re-apply rules to every known domain. Returns number of domains whose classification changed."""
    m = Matcher(conn)
    changed = []
    for did, name, service, category, autoblock in conn.execute(
        "SELECT id, name, service, category, autoblock FROM domains"
    ).fetchall():
        s, c = m.classify(name, bool(autoblock))
        if (s, c) != (service, category):
            changed.append((s, c, did))
    conn.executemany("UPDATE domains SET service=?, category=? WHERE id=?", changed)
    return len(changed)
