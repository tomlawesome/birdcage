#!/usr/bin/env python3
"""attack.py -- the attacker and the stopwatch for scripts/e2e/live-check.sh.

Pure standard library, because the check runs on a host with no route to a
package mirror and an Alpine/Debian client image (nmap, smbclient, snmpget,
mysql) cannot be built there. Every trip below speaks just enough of the
real wire protocol for OpenCanary or the agent to log it, against the one
canary the harness started and nothing else.

  attack.py trip <lure> <host>                  send one trip, print JSON
  attack.py baseline <canary-id>                print the highest alert id held
  attack.py poll <service> <canary-id> <after-id> <timeout-s> [marker]
                                                wait for a newer alert
  attack.py health <canary-id> <interval-s> <outfile>
                                                sample status until killed
  attack.py canary <canary-id>                  print /api/canary as JSON
  attack.py dump <canary-id>                    every alert the canary holds
  attack.py smbclient -L //host -N              share list (see smb_list)

trip, baseline and poll need different containers: trip runs in the attacker
(no credentials), the other three in the probe (dashboard token and CA).
Both read the one host clock, so a trip's start and an alert's first sighting
subtract cleanly.
"""
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

DASHBOARD = os.environ.get("BIRDCAGE_URL", "")


# ---------------------------------------------------------------- dashboard

def api(path):
    ctx = ssl.create_default_context(cafile="/tls/dashboard-ca.pem")
    # Python 3.13 insists a CA carry a key-usage extension; the harness's
    # throwaway CA does not. The chain and host name are still verified.
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    token = ""
    with open("/work/dashboard-auth") as f:
        token = f.read().strip().split(":", 1)[1].strip()
    req = urllib.request.Request(DASHBOARD + path, headers={"Authorization": token})  # noqa: S310 -- DASHBOARD is a fixed https URL of the harness's own throwaway container
    with urllib.request.urlopen(req, context=ctx, timeout=10) as r:  # noqa: S310 -- fixed https URL, see above
        return json.load(r)


def alerts(canary, service=None):
    q = {"instance": canary}
    if service:
        q["service"] = service
    return api("/api/alerts?" + urllib.parse.urlencode(q))["alerts"]


def summarise(a):
    raw = {}
    try:
        raw = json.loads(a.get("raw") or "{}")
    except ValueError:
        pass
    return {
        "id": a["id"],
        "service": a["service"],
        "source_ip": a["source_ip"],
        "dest_port": a["dest_port"],
        "received_at": a["received_at"],
        "synthetic": a.get("synthetic"),
        "logtype": raw.get("logtype"),
        "src_host": raw.get("src_host"),
        "src_port": raw.get("src_port"),
        "dst_port": raw.get("dst_port"),
        "utc_time": raw.get("utc_time"),
        "logdata": raw.get("logdata"),
        "raw_keys": sorted(raw.keys()),
    }


def cmd_baseline(canary):
    ids = [a["id"] for a in alerts(canary)]
    print(max(ids) if ids else 0)


def cmd_poll(service, canary, after, timeout, marker=None):
    after = int(after)
    start = time.time()
    first = None
    seen = {}
    while time.time() - start < float(timeout):
        try:
            for a in alerts(canary, service):
                if a["id"] > after and a["id"] not in seen:
                    if marker and marker not in (a.get("raw") or ""):
                        continue
                    seen[a["id"]] = a
                    if first is None:
                        first = time.time()
        except Exception as e:  # keep polling through a blip, but say so
            print("poll: " + str(e), file=sys.stderr)
        if first is not None and time.time() - first > 6:
            break  # settle window: catch a second alert from one trip
        time.sleep(0.25)
    print(json.dumps({
        "poll_started": start,
        "first_seen": first,
        "alerts": [summarise(a) for a in sorted(seen.values(), key=lambda a: a["id"])],
    }))


def cmd_dump(canary):
    print(json.dumps([summarise(a) for a in sorted(alerts(canary), key=lambda a: a["id"])]))


def cmd_canary(canary):
    d = api("/api/canary?id=" + canary)
    runs = d.get("self_test_runs") or []
    print(json.dumps({
        "canary": {k: d["canary"].get(k) for k in ("status", "active_states", "hits", "last_heartbeat_at", "ports")},
        "self_test_runs": runs[:3],
        "self_test_keys": sorted(d.keys()),
    }))


def cmd_health(canary, interval, outfile):
    while True:
        row = {"t": time.time()}
        try:
            c = [x for x in api("/api/canaries")["canaries"] if x["id"] == canary][0]
            row.update(status=c["status"], active_states=c.get("active_states") or [],
                       hits=c.get("hits"), last_heartbeat_at=c.get("last_heartbeat_at"))
        except Exception as e:
            row["error"] = str(e)
        with open(outfile, "a") as f:
            f.write(json.dumps(row) + "\n")
        time.sleep(float(interval))


# ------------------------------------------------------------------- trips

def tcp(host, port, timeout=5):
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def rd(s, n=4096):
    try:
        return s.recv(n)
    except socket.timeout:
        return b""


def udp(host, port, payload, wait=2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(wait)
    s.sendto(payload, (host, port))
    try:
        return s.recvfrom(4096)[0]
    except socket.timeout:
        return b""
    finally:
        s.close()


def trip_ftp(host):
    s = tcp(host, 21)
    banner = rd(s)
    for line in (b"USER live-check\r\n", b"PASS not-a-password\r\n", b"QUIT\r\n"):
        s.sendall(line)
        rd(s)
    s.close()
    return {"command": "FTP USER/PASS/QUIT on 21", "banner": banner.decode(errors="replace").strip()}


def trip_ssh(host, legacy=True):
    askpass = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False)
    askpass.write("#!/bin/sh\necho not-a-password\n")
    askpass.close()
    os.chmod(askpass.name, 0o755)  # noqa: S103 -- throwaway askpass script in the harness's temp dir; ssh refuses a non-executable one
    env = dict(os.environ, SSH_ASKPASS=askpass.name, SSH_ASKPASS_REQUIRE="force", DISPLAY="x")
    p = subprocess.run(  # noqa: S603 -- fixed argv, no shell; host is a harness container address
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
         "-o", "NumberOfPasswordPrompts=1", "-o", "ConnectTimeout=5",
         ] + (["-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
               "-o", "HostKeyAlgorithms=+ssh-rsa"] if legacy else []) + [
         "-o", "LogLevel=ERROR", "live-check@" + host, "true"],
        env=env, capture_output=True, text=True, timeout=30)
    os.unlink(askpass.name)
    return {"command": "ssh password login (wrong password) on 22, %s" % (
                "legacy KEX/host-key algorithms enabled" if legacy else "this client's defaults"),
            "rc": p.returncode,
            "stderr": p.stderr.strip()[-300:]}


def trip_ssh_default(host):
    return trip_ssh(host, legacy=False)


def trip_telnet(host):
    s = tcp(host, 23)
    out = rd(s)
    s.sendall(b"admin\r\n")
    out += rd(s)
    s.sendall(b"not-a-password\r\n")
    out += rd(s)
    s.close()
    return {"command": "telnet login prompt, admin / wrong password on 23", "reply": out.decode(errors="replace")[:200]}


def trip_http(host):
    p = subprocess.run(  # noqa: S603 -- fixed argv, no shell; host is a harness container address
        ["curl", "-sS", "-m", "10", "-o", "/dev/null", "-w", "http=%{http_code}",  # noqa: S607 -- curl on PATH in the live-check container
         "-d", "username=admin&password=not-a-password", "http://%s/index.html" % host],
        capture_output=True, text=True)
    return {"command": "curl POST username/password to http://<canary>/ on 80", "result": p.stdout, "err": p.stderr.strip()}


def trip_mysql(host):
    s = tcp(host, 3306)
    greeting = rd(s)
    caps = 0x00000001 | 0x00000004 | 0x00000200 | 0x00008000
    body = struct.pack("<IIB", caps, 1 << 24, 33) + b"\x00" * 23
    body += b"root\x00" + bytes([20]) + os.urandom(20)
    s.sendall(struct.pack("<I", len(body))[:3] + b"\x01" + body)
    reply = rd(s)
    s.close()
    return {"command": "MySQL handshake response, user root, bad scramble on 3306",
            "greeting_bytes": len(greeting), "reply_bytes": len(reply)}


def tds(ptype, payload, pid=1):
    return struct.pack(">BBHHBB", ptype, 1, len(payload) + 8, 0, pid, 0) + payload


def trip_mssql(host):
    s = tcp(host, 1433)
    # PRELOGIN: VERSION option, then terminator.
    pre = bytes([0x00]) + struct.pack(">HH", 6, 6) + b"\xff" + b"\x0f\x00\x00\x00\x00\x00"
    s.sendall(tds(0x12, pre))
    rd(s)

    def ucs(t):
        return t.encode("utf-16-le")

    def pw(t):
        out = bytearray()
        for b in ucs(t):
            out.append((((b & 0x0F) << 4) | (b >> 4)) ^ 0xA5)
        return bytes(out)

    host_n, user, pwd, app, srv = "attacker", "sa", "not-a-password", "live-check", host
    fields = [ucs(host_n), ucs(user), pw(pwd), ucs(app), ucs(srv), b"", ucs("live"), b"", ucs("master")]
    counts = [len(host_n), len(user), len(pwd), len(app), len(srv), 0, 4, 0, 6]
    base = 94
    off, offs = base, []
    for f in fields:
        offs.append(off)
        off += len(f)
    fixed = struct.pack("<IIIIIIBBBBiI", 0, 0x74000004, 4096, 7, 1234, 0, 0xE0, 0x03, 0, 0, 0, 0x0409)
    pairs = b"".join(struct.pack("<HH", o, c) for o, c in zip(offs, counts))
    tail = b"\x00" * 6 + struct.pack("<HH", off, 0) + struct.pack("<HH", off, 0) + struct.pack("<HH", off, 0) + struct.pack("<I", 0)
    data = fixed + pairs + tail + b"".join(fields)
    data = struct.pack("<I", len(data)) + data[4:]
    s.sendall(tds(0x10, data, 2))
    reply = rd(s)
    s.close()
    return {"command": "TDS prelogin then Login7 as sa, wrong password on 1433", "reply_bytes": len(reply)}


def trip_redis(host):
    s = tcp(host, 6379)
    s.sendall(b"*1\r\n$4\r\nINFO\r\n")
    reply = rd(s)
    s.sendall(b"*2\r\n$4\r\nAUTH\r\n$14\r\nnot-a-password\r\n")
    rd(s)
    s.close()
    return {"command": "RESP INFO then AUTH on 6379", "reply": reply.decode(errors="replace")[:80]}


def trip_rdp(host):
    cookie = b"Cookie: mstshash=live-check\r\n"
    x224 = bytes([6 + len(cookie) + 8, 0xE0, 0, 0, 0, 0, 0]) + cookie + bytes([1, 0, 8, 0, 3, 0, 0, 0])
    pkt = struct.pack(">BBH", 3, 0, 4 + len(x224)) + x224
    s = tcp(host, 3389)
    s.sendall(pkt)
    reply = rd(s)
    s.close()
    return {"command": "X.224 connection request with mstshash cookie on 3389", "reply_bytes": len(reply)}


def trip_sip(host):
    msg = ("OPTIONS sip:100@%s SIP/2.0\r\nVia: SIP/2.0/UDP attacker:5060;branch=z9hG4bK-live\r\n"
           "From: <sip:live-check@attacker>;tag=1\r\nTo: <sip:100@%s>\r\nCall-ID: live-check-1\r\n"
           "CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n") % (host, host)
    reply = udp(host, 5060, msg.encode())
    return {"command": "UDP SIP OPTIONS on 5060", "reply_bytes": len(reply)}


def trip_tftp(host):
    reply = udp(host, 69, b"\x00\x01live-check.cfg\x00octet\x00")
    return {"command": "UDP TFTP read request for live-check.cfg on 69", "reply_bytes": len(reply)}


def ber(tag, body):
    n = len(body)
    ln = bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 255])
    return bytes([tag]) + ln + body


def trip_snmp(host, community="live-check-snmp"):
    oid = bytes([0x2B, 6, 1, 2, 1, 1, 1, 0])
    varbind = ber(0x30, ber(0x30, ber(0x06, oid) + ber(0x05, b"")))
    pdu = ber(0xA0, ber(2, b"\x2a") + ber(2, b"\x00") + ber(2, b"\x00") + varbind)
    msg = ber(0x30, ber(2, b"\x01") + ber(4, community.encode()) + pdu)
    reply = udp(host, 161, msg)
    return {"command": "SNMPv2c GetRequest sysDescr.0, community %s, on 161/udp" % community,
            "community": community, "reply_bytes": len(reply)}


def trip_portscan(host):
    results = {}
    for port in range(20000, 20005):
        s = socket.socket()
        s.settimeout(1)
        results[port] = s.connect_ex((host, port))
        s.close()
    return {"command": "TCP connect to closed ports 20000-20004", "connect_ex": results}


# ---- SMB2: negotiate, anonymous NTLMSSP, tree connect, open + read + close.
# The shipped smbclient needs a package mirror this host cannot reach; this is
# the smallest client that makes Samba open and close a bait file for real.

def smb_hdr(cmd, mid, sid=0, tid=0):
    return struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 1, 0, cmd, 1, 0, 0, mid, 0, tid, sid, b"\0" * 16)


def smb_send(s, cmd, mid, body, sid=0, tid=0):
    pkt = smb_hdr(cmd, mid, sid, tid) + body
    s.sendall(b"\x00" + struct.pack(">I", len(pkt))[1:] + pkt)


def smb_recv(s):
    h = b""
    while len(h) < 4:
        c = s.recv(4 - len(h))
        if not c:
            raise IOError("SMB connection closed")
        h += c
    n = struct.unpack(">I", b"\x00" + h[1:])[0]
    d = b""
    while len(d) < n:
        c = s.recv(n - len(d))
        if not c:
            raise IOError("SMB connection closed")
        d += c
    status = struct.unpack_from("<I", d, 8)[0]
    sid = struct.unpack_from("<Q", d, 40)[0]
    tid = struct.unpack_from("<I", d, 36)[0]
    return status, sid, tid, d[64:]


def ntlm_negotiate():
    flags = 0x1 | 0x2 | 0x4 | 0x200 | 0x8000 | 0x80000 | 0x20000000 | 0x80000000
    return b"NTLMSSP\0" + struct.pack("<IIHHIHHI", 1, flags, 0, 0, 0, 0, 0, 0)


def ntlm_anonymous_auth():
    flags = 0x1 | 0x200 | 0x8000 | 0x80000 | 0x20000000 | 0x80000000
    lm = b"\x00"
    base = 72
    body = b"NTLMSSP\0" + struct.pack("<I", 3)
    pos = base
    for blob in (lm, b"", b"", b"", b"", b""):
        body += struct.pack("<HHI", len(blob), len(blob), pos)
        pos += len(blob)
    body += struct.pack("<I", flags) + b"\0" * 8
    return body + lm


def smb_session(host, share):
    s = tcp(host, 445)
    smb_send(s, 0, 0, struct.pack("<HHHHI16sQ", 36, 2, 1, 0, 0, b"\1" * 16, 0) + struct.pack("<HH", 0x0202, 0x0210))
    st, _, _, _ = smb_recv(s)
    if st != 0:
        raise IOError("negotiate status %#x" % st)

    def setup(token, sid, mid):
        body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(token), 0) + token
        smb_send(s, 1, mid, body, sid)
        return smb_recv(s)

    st, sid, _, _ = setup(ntlm_negotiate(), 0, 1)
    if st != 0xC0000016:
        raise IOError("session setup 1 status %#x" % st)
    st, sid2, _, _ = setup(ntlm_anonymous_auth(), sid, 2)
    if st != 0:
        raise IOError("session setup 2 status %#x" % st)
    path = ("\\\\%s\\%s" % (host, share)).encode("utf-16-le")
    smb_send(s, 3, 3, struct.pack("<HHHH", 9, 0, 72, len(path)) + path, sid)
    st, _, tid, _ = smb_recv(s)
    return s, sid, tid, st


def smb_open_close(host, share, path):
    s, sid, tid, st = smb_session(host, share)
    if st != 0:
        raise IOError("tree connect status %#x" % st)
    name = path.replace("/", "\\").encode("utf-16-le")
    body = struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, 0x00120089, 0, 1, 1, 0x40, 120, len(name), 0, 0) + name
    smb_send(s, 5, 4, body, sid, tid)
    st, _, _, rbody = smb_recv(s)
    if st != 0:
        raise IOError("create %s status %#x" % (path, st))
    fid = rbody[64:80]
    smb_send(s, 6, 5, struct.pack("<HHI", 24, 0, 0) + fid, sid, tid)
    smb_recv(s)
    s.close()


def smb_list(host):
    seen = []
    for share in ("public", "backup", "scans"):
        try:
            s, _, _, st = smb_session(host, share)
            s.close()
            if st == 0:
                seen.append(share)
        except Exception:  # noqa: S110 -- a share that will not open is simply not listed
            pass
    return seen


def trip_smb(host):
    smb_open_close(host, "public", "IT/vpn-setup.pdf")
    return {"command": "SMB2 anonymous session, open + close \\\\<canary>\\public\\IT\\vpn-setup.pdf on 445"}


TRIPS = {
    "ftp": trip_ftp, "ssh": trip_ssh, "ssh-modern": trip_ssh_default, "telnet": trip_telnet, "http": trip_http,
    "mysql": trip_mysql, "mssql": trip_mssql, "redis": trip_redis, "rdp": trip_rdp,
    "sip": trip_sip, "tftp": trip_tftp, "snmp": trip_snmp, "portscan": trip_portscan,
    "smb": trip_smb,
}


def cmd_trip(lure, host):
    t0 = time.time()
    err = None
    info = {}
    try:
        info = TRIPS[lure](host)
    except Exception as e:
        err = "%s: %s" % (type(e).__name__, e)
    print(json.dumps({"lure": lure, "trip_start": t0, "trip_end": time.time(),
                      "attacker": socket.gethostbyname(socket.gethostname()), "error": err, **info}))


def main(argv):
    c = argv[1] if len(argv) > 1 else ""
    a = argv[2:]
    if c == "trip":
        cmd_trip(*a)
    elif c == "baseline":
        cmd_baseline(*a)
    elif c == "poll":
        cmd_poll(*a)
    elif c == "health":
        cmd_health(*a)
    elif c == "canary":
        cmd_canary(*a)
    elif c == "dump":
        cmd_dump(*a)
    elif c == "smbclient":
        # smbclient -L //host -N: lists the shares a tree connect reaches.
        host = a[1].lstrip("/")
        print("\tSharename       Type      Comment\n\t---------       ----      -------")
        for sh in smb_list(host):
            print("\t%-15s Disk" % sh)
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
