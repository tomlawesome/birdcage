// Package smbaudit reads the log file the SMB lure writes
// (build/smb-lure) and turns each line into an event the canary agent can
// queue (issue #87, decision 40b).
//
// # Why this parse is ours and not OpenCanary's
//
// OpenCanary ships an `smb` module that tails the same kind of file, and
// it is not used -- docs/opencanary.md records the decision. It starts
// reading at end-of-file, so every restart has a window in which access
// is not delayed but gone; it picks fields by fixed index, so a line
// whose shape shifts yields wrong values rather than an error; and it
// only matches lines that went through syslog(3), which puts a syslog
// daemon inside the container built to be attacked. The agent's own
// tailer (internal/agent/tailer) already solves the first of those --
// saved position, rotation-aware -- and this package is the second and
// third: it fails loudly on a shape it does not recognise, and it reads
// what vfs_full_audit writes straight to a file.
//
// # The line this expects
//
// The lure's smb.conf sets `full_audit:prefix = %U|%I|%S`,
// `full_audit:success = close` and `debug prefix timestamp = yes`, so one
// audit record is one line:
//
//	[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf
//
// captured from a real smbclient against the real image on 2026-09-23,
// not written from the documentation. Six fields after the debug header:
// the user name the client asked for, the source address, the share, the
// operation, its result, and the path.
//
// # Why the fields are counted from the right
//
// `%U` is whatever user name the client sent. Samba does replace the
// separators it knows about before writing it -- a client asking for
// `a|b` appears as `a_b`, also verified by running it -- but nothing in
// this package leans on that: it counts the operation, the result and the
// path from the end of the line, so even a user name that did contain the
// separator could not move them. The user name absorbs any extra field
// instead, which is the one place a wrong value costs nothing.
//
// # The shifted openat line, and why it is refused
//
// `close` is audited rather than `open` because on SMB2 a file open
// arrives as the openat operation, whose audit message carries an extra
// "r"/"w" field ahead of the path:
//
//	root|172.21.0.3|public|openat|ok|r|/srv/shares/public/IT/vpn-setup.pdf
//
// A parse that reads by position would take "r" for the filename, which
// is #78's note, finding 2. This package refuses that line: the field
// where a result belongs has to be exactly "ok" or "fail", and "r" is
// neither, so the line becomes an "unparseable audit line" event rather
// than a quietly wrong one. An unrecognised line is always an event --
// never a silent skip -- because a line this package cannot read is
// itself something an operator needs to know about.
//
// # Everything here is hostile input
//
// The share holds nothing but what the image put there, so a path in an
// audit line is not attacker-chosen; the user name in the same line is.
// Beyond that, this file is written by a process whose whole purpose is
// to be attacked, on a volume the agent mounts read-only: a compromised
// smbd can write anything it likes into it. So nothing here allocates
// from a length in the input, every field is bounded before it is copied,
// and no value is interpreted beyond splitting on the separator.
package smbaudit
