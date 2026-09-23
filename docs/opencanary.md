# How birdcage uses OpenCanary

Mockingbird, the agent image, runs upstream
[OpenCanary](https://github.com/thinkst/opencanary) unmodified and reads
its log. This page records which parts we rely on, which parts we
deliberately do not use, and why -- so a reader knows what is a choice
and what is an accident, and that nothing is sent upstream. Owner, 2026-09-23: no tracker issue for this; the
record lives here.

## What we use

- The emulated services and their log lines: ssh, telnet, ftp, http,
  mysql, smb (the parse of `logdata`, `internal/store/visitor.go`
  `triedFor`), portscan, snmp, vnc. The self-test grades of proof (#46)
  rest on those lines carrying the probe's marker.
- The log file, tailed by the agent (`internal/agent/tailer`) with a
  saved position, so a canary restart loses nothing.

## What we route round, and why

| OpenCanary piece | What we do instead | Why | Where decided |
|---|---|---|---|
| `llmnr` module | The agent sends the bait queries itself | The module imports scapy (not in the image) and its send needs a raw socket, which uid 65532 cannot open; one failure kills its timer for good. Listening alone catches nothing. | #85, #86 |
| `smb` module (reads Samba's `full_audit` file) | The agent tails the audit file with its own tailer and parse | The module starts at end-of-file (a blind window on every restart), picks fields by fixed index (a shifted line gives wrong values, not an error), and only matches lines that went through syslog, so a syslog daemon has to ride along. | #78 note, #87 |
| Start-up lines (logtype 1000-1006, service `base`) | Acked on ingest, never stored or counted | They are OpenCanary announcing its own modules, not visitors; before #117 a fresh canary showed ~11 hits of nothing. The agent still forwards them because #65 will read which modules started. | #117 |
| `full_audit:success = open` (upstream wiki) | `close` | On SMB2 the open message carries an extra field ahead of the path. | #78 note |

## Nothing goes upstream

Birdcage will never submit a pull request to OpenCanary (owner,
2026-09-23). Where its behaviour does not suit us, we route round it in
our own code, as the table above records; we do not patch, fork or
carry changes to it.

## Still to do

A review, at some point, of what else in how we run OpenCanary is
low-hanging fruit for our own use -- configuration we inherit by default,
modules we leave on without a reason, log fields we ignore. Tracked as #122 (owner, 2026-09-23).
