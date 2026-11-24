#!/usr/bin/env python3
"""report.py <out-dir> -- turn live-check.sh's raw results into tables.

Prints Markdown to stdout and writes <out-dir>/summary.json. Reads, per lure,
<lure>.trip.json (what the attacker did and when) and <lure>.poll.json (when
the alert first showed in GET /api/alerts, and its fields), plus the health
samples. Nothing here talks to a container.
"""
import datetime
import json
import os
import sys

out = sys.argv[1]
SYSDESCR_OID = ".".join(["1", "3", "6", "1", "2", "1", "1", "1", "0"])
ADDR = "<attacker>"


def load(name):
    try:
        with open(os.path.join(out, name)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def ts(s):
    s = s.rstrip("Z")
    if "." in s:
        head, frac = s.split(".")
        s = head + "." + frac[:6]
    return datetime.datetime.fromisoformat(s).replace(tzinfo=datetime.timezone.utc).timestamp()


# lure -> (expected service, expected dest_port, check(alert) -> (ok, why))
def has(key, want):
    return lambda a: ((a.get("logdata") or {}).get(key) == want, "%s=%r" % (key, (a.get("logdata") or {}).get(key)))


EXPECT = {
    "ftp": ("ftp", 21, lambda a: (has("USERNAME", "live-check")(a)[0] and has("PASSWORD", "not-a-password")(a)[0], "USERNAME/PASSWORD")),
    "ssh": ("ssh", 22, lambda a: ((a.get("logdata") or {}).get("USERNAME") == "live-check" or a.get("logtype") in (4000, 4001), "logtype %s" % a.get("logtype"))),
    "ssh-modern": ("ssh", 22, lambda a: ((a.get("logdata") or {}).get("USERNAME") == "live-check", "USERNAME (needs a login attempt: logtype 4002)")),
    "telnet": ("telnet", 23, has("USERNAME", "admin")),
    "http": ("http", 80, has("USERNAME", "admin")),
    "mysql": ("mysql", 3306, has("USERNAME", "root")),
    "mssql": ("mssql", 1433, has("UserName", "sa")),
    "redis": ("redis", 6379, has("CMD", "INFO")),
    "rdp": ("rdp", 3389, has("USERNAME", "live-check")),
    "sip": ("sip", 5060, lambda a: ("live-check-1" in json.dumps(a.get("logdata")), "Call-ID")),
    "tftp": ("tftp", 69, has("FILENAME", "live-check.cfg")),
    "snmp": ("snmp", 161, lambda a: ((a.get("logdata") or {}).get("COMMUNITY_STRING") == "live-check-snmp"
                                       and SYSDESCR_OID in ((a.get("logdata") or {}).get("REQUESTS") or []), "community + OID")),
    "portscan": ("portscan", None, lambda a: (all(str(p) in (a.get("logdata") or {}).get("PORTS", "") for p in range(20000, 20005)),
                                               "PORTS=%s" % (a.get("logdata") or {}).get("PORTS"))),
    "smb": ("smb", 445, lambda a: ((a.get("logdata") or {}).get("FILENAME", "").endswith("IT/vpn-setup.pdf")
                                   and (a.get("logdata") or {}).get("SHARENAME") == "public", "FILENAME/SHARENAME")),
}

rows = []
print("| lure | tripped? | alert seen? | seconds to alert (first seen) | seconds to birdcage receipt | alerts | fields correct? | notes |")
print("|---|---|---|---|---|---|---|---|")
for lure, (service, port, check) in EXPECT.items():
    trip, poll = load(lure + ".trip.json"), load(lure + ".poll.json")
    if not trip:
        print("| %s | no | no | - | - | 0 | - | the trip produced no output |" % lure)
        continue
    tripped = trip.get("error") is None
    alerts = (poll or {}).get("alerts") or []
    seen = (poll or {}).get("first_seen")
    first = alerts[0] if alerts else None
    delta = round(seen - trip["trip_start"], 2) if seen else None
    recv = round(ts(first["received_at"]) - trip["trip_start"], 2) if first else None
    notes = []
    if trip.get("error"):
        notes.append("trip error: %s" % trip["error"])
    ok = False
    if alerts:
        good = []
        for a in alerts:
            sv_ok = a["service"] == service
            src_ok = a["source_ip"] == trip.get("attacker")
            port_ok = port is None or a["dest_port"] == port
            fld_ok, why = check(a)
            good.append(sv_ok and src_ok and fld_ok and (port_ok or port is None))
            if not src_ok:
                notes.append("source %s != attacker %s" % (a["source_ip"], trip.get("attacker")))
            if not port_ok:
                notes.append("dest_port %s want %s" % (a["dest_port"], port))
        ok = any(good)
        if port is None:
            notes.append("dest_port shown: %s" % ", ".join(sorted({str(a["dest_port"]) for a in alerts})))
        notes.append("logtypes %s" % ",".join(str(a["logtype"]) for a in alerts))
    rows.append({"lure": lure, "tripped": tripped, "seen": bool(alerts), "delta": delta, "received": recv,
                 "count": len(alerts), "fields_ok": ok, "alerts": alerts, "trip": trip})
    print("| %s | %s | %s | %s | %s | %d | %s | %s |" % (
        lure, "yes" if tripped else "no", "yes" if alerts else "NO",
        delta if delta is not None else "-", recv if recv is not None else "-", len(alerts),
        "yes" if ok else ("NO" if alerts else "-"), "; ".join(notes).replace("172.", "<net>.")))

# poisoner
pol = load("poisoner.poll.json") or {}
meta = {}
try:
    for line in open(os.path.join(out, "poisoner.meta.txt")):
        k, _, v = line.strip().partition("=")
        meta[k] = v
except OSError:
    pass
print()
print("Poisoner (canary baits on its own schedule; no trip time, clock runs from the canary's start):")
for a in pol.get("alerts") or []:
    started = meta.get("canary_started")
    after = round(ts(a["received_at"]) - ts(started), 1) if started else None
    print("- alert id %s service %s: %s seconds after canary start; logdata %s; source is the answerer: %s" % (
        a["id"], a["service"], after, json.dumps(a["logdata"]), meta.get("fixture_address_matches_alert_source")))
if not pol.get("alerts"):
    print("- NO poisoner alert arrived before the watcher timed out")

# extra portscan check
x = load("portscan-after-smb.poll.json") or {}
print()
print("Extra: one SMB visit then four closed ports -> portscan alerts: %d %s" % (
    len(x.get("alerts") or []), json.dumps([a["logdata"] for a in x.get("alerts") or []])))

# every alert the canary holds, by service and source
allx = load("alerts-all.json") or []
atk = (load("ssh.trip.json") or {}).get("attacker")
fixture_ip = None
print()
print("Every alert the canary holds, by service and source (attacker = %s; other sources named below):" % ADDR)
groups = {}
for a in allx:
    who = "attacker" if a["source_ip"] == atk else a["source_ip"].replace("172.", "<net>.")
    groups.setdefault((a["service"], who), []).append(a["id"])
for (svc, who), ids in sorted(groups.items()):
    print("- %s from %s: %d (ids %s)" % (svc, who, len(ids), ",".join(map(str, ids[:6])) + ("..." if len(ids) > 6 else "")))
json.dump(allx, open(os.path.join(out, "alerts-all.summary.json"), "w"))

# health
samples = []
try:
    samples = [json.loads(l) for l in open(os.path.join(out, "health-samples.jsonl"))]
except OSError:
    pass
print()
print("Health samples (every 5 s): %d" % len(samples))
combos = {}
for s in samples:
    k = "%s %s" % (s.get("status"), ",".join(s.get("active_states") or []) or "-")
    combos.setdefault(k, 0)
    combos[k] += 1
for k, n in sorted(combos.items()):
    print("- %s: %d samples" % (k, n))
for name in ("health-before.json", "health-after.json"):
    d = load(name)
    if d:
        print("%s: status %s, active_states %s, hits %s, self-test runs %s" % (
            name, d["canary"]["status"], d["canary"]["active_states"], d["canary"]["hits"],
            json.dumps(d["self_test_runs"])))

json.dump({"rows": rows, "health_samples": len(samples)}, open(os.path.join(out, "summary.json"), "w"), indent=1)
