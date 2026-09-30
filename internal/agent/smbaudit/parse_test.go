package smbaudit

import (
	"strings"
	"testing"
)

// The lines marked "captured" below are verbatim copies out of
// /audit/smb.log from the real build/smb-lure image, run under the
// hardening flags in its README and driven by a real smbclient, on
// 2026-09-23. They are not written from Samba's documentation, and the
// panic lines are not synthesised either: they are what the container
// actually wrote when it was started without CAP_SETGID and then without
// CAP_SETUID. If the image's smb.conf ever changes the prefix or the
// audited operation, these are the lines that stop matching.
func TestParse(t *testing.T) {
	tests := []struct {
		name string
		line string

		wantOK    bool
		wantKind  Kind
		wantUser  string
		wantIP    string
		wantShare string
		wantOp    string
		wantRes   string
		wantPath  string
		wantMsgIn string // substring of Event.Message, when one is expected
	}{
		{
			name:      "captured: a file fetched over SMB2",
			line:      `[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
			wantOK:    true,
			wantKind:  KindAccess,
			wantUser:  "root",
			wantIP:    "172.21.0.3",
			wantShare: "public",
			wantOp:    "close",
			wantRes:   "ok",
			wantPath:  "/srv/shares/public/IT/vpn-setup.pdf",
		},
		{
			name:      "captured: a directory listed is a close on the directory",
			line:      `[2026/09/23 22:01:53.984095,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public`,
			wantOK:    true,
			wantKind:  KindAccess,
			wantUser:  "root",
			wantIP:    "172.21.0.3",
			wantShare: "public",
			wantOp:    "close",
			wantRes:   "ok",
			wantPath:  "/srv/shares/public",
		},
		{
			name: "captured: Samba replaced the separator in a client-chosen user name",
			// The client asked for the user name `a|b`; Samba wrote a_b.
			line:      `[2026/09/23 22:01:54.114139,  1]   a_b|172.21.0.3|backup|close|ok|/srv/shares/backup/router-config.txt`,
			wantOK:    true,
			wantKind:  KindAccess,
			wantUser:  "a_b",
			wantIP:    "172.21.0.3",
			wantShare: "backup",
			wantOp:    "close",
			wantRes:   "ok",
			wantPath:  "/srv/shares/backup/router-config.txt",
		},
		{
			name: "captured: the shifted openat shape is refused, never read as a path",
			// Issue #78's note, finding 2: the extra "r" sits where a
			// result belongs. A fixed-index parse would report "r" as the
			// filename.
			line:      `[2026/09/23 22:02:29.216096,  1]   root|172.21.0.3|public|openat|ok|r|/srv/shares/public/IT/vpn-setup.pdf`,
			wantOK:    true,
			wantKind:  KindUnparseable,
			wantMsgIn: `"r" where the result belongs`,
		},
		{
			name:      "captured: smbd's internal-error line",
			line:      `[2026/09/23 22:06:57.659859,  0]   INTERNAL ERROR: sys_setgroups failed in smbd () () pid 1 (4.23.8)`,
			wantOK:    true,
			wantKind:  KindPanic,
			wantMsgIn: "sys_setgroups failed",
		},
		{
			name:      "captured: smbd's panic line",
			line:      `[2026/09/23 22:06:57.659891,  0]   PANIC (pid 1): sys_setgroups failed in 4.23.8`,
			wantOK:    true,
			wantKind:  KindPanic,
			wantMsgIn: "PANIC (pid 1)",
		},
		{
			name:      "captured: a per-connection child panicking on the uid switch",
			line:      `[2026/09/23 22:07:34.302272,  0]   PANIC (pid 36): failed to set uid`,
			wantOK:    true,
			wantKind:  KindPanic,
			wantMsgIn: "failed to set uid",
		},
		{
			name:   "captured: the start-up banner is not an event",
			line:   `[2026/09/23 21:59:09.210719,  0]   smbd version 4.23.8 started.`,
			wantOK: false,
		},
		{
			name:   "captured: a continuation line has no debug header and is not an event",
			line:   `  Copyright Andrew Tridgell and the Samba Team 1992-2025`,
			wantOK: false,
		},
		{
			name:   "captured: a configuration complaint is not an event",
			line:   `[2026/09/23 22:01:53.968041,  0]   Unknown parameter encountered: "dump core"`,
			wantOK: false,
		},
		{
			name:   "captured: the panic banner rule is not an event",
			line:   `[2026/09/23 22:06:57.659883,  0]   ===============================================================`,
			wantOK: false,
		},
		{
			name:   "captured: the stack-trace note is not an event",
			line:   `[2026/09/23 22:06:57.659900,  0]   unable to produce a stack trace on this platform`,
			wantOK: false,
		},
		{
			name: "a separator inside the user name cannot move the path",
			// Samba sanitises this today (see the captured case above),
			// and nothing here relies on that: counted from the right,
			// the extra field lands in the user name, which is the one
			// place a wrong value costs nothing.
			line:      `[2026/09/23 22:01:53.987124,  1]   a|b|172.21.0.3|public|close|ok|/srv/shares/public/IT/vpn-setup.pdf`,
			wantOK:    true,
			wantKind:  KindAccess,
			wantUser:  "a|b",
			wantIP:    "172.21.0.3",
			wantShare: "public",
			wantOp:    "close",
			wantRes:   "ok",
			wantPath:  "/srv/shares/public/IT/vpn-setup.pdf",
		},
		{
			name: "a two-argument operation is refused rather than misread",
			// renameat writes the old and the new path. The old path
			// lands where a result belongs, so the line is refused --
			// which is what stops the new path being reported as the
			// whole story.
			line:      `[2026/09/23 22:02:29.216096,  1]   root|172.21.0.3|public|renameat|ok|/srv/shares/public/a|/srv/shares/public/b`,
			wantOK:    true,
			wantKind:  KindUnparseable,
			wantMsgIn: "where the result belongs",
		},
		{
			name:      "a well-formed line outside the expected operation set",
			line:      `[2026/09/23 22:02:29.216096,  1]   root|172.21.0.3|public|unlinkat|ok|/srv/shares/public/IT/vpn-setup.pdf`,
			wantOK:    true,
			wantKind:  KindUnexpectedOperation,
			wantUser:  "root",
			wantIP:    "172.21.0.3",
			wantShare: "public",
			wantOp:    "unlinkat",
			wantRes:   "ok",
			wantPath:  "/srv/shares/public/IT/vpn-setup.pdf",
		},
		{
			name:      "a failed operation is well-formed and keeps its result",
			line:      `[2026/09/23 22:02:29.216096,  1]   root|172.21.0.3|scans|close|fail|/srv/shares/scans/x.pdf`,
			wantOK:    true,
			wantKind:  KindAccess,
			wantUser:  "root",
			wantIP:    "172.21.0.3",
			wantShare: "scans",
			wantOp:    "close",
			wantRes:   "fail",
			wantPath:  "/srv/shares/scans/x.pdf",
		},
		{
			name:      "a truncated audit line is reported, not skipped",
			line:      `[2026/09/23 22:02:29.216096,  1]   root|172.21.0.3|public`,
			wantOK:    true,
			wantKind:  KindUnparseable,
			wantMsgIn: "3 fields, expected at least 6",
		},
		{
			name:      "a non-name where the operation belongs is refused",
			line:      `[2026/09/23 22:02:29.216096,  1]   root|172.21.0.3|public|CLOSE!|ok|/srv/shares/public/x`,
			wantOK:    true,
			wantKind:  KindUnparseable,
			wantMsgIn: "where the operation belongs",
		},
		{
			name:      "an empty operation is refused",
			line:      `[2026/09/23 22:02:29.216096,  1]   root|172.21.0.3|public||ok|/srv/shares/public/x`,
			wantOK:    true,
			wantKind:  KindUnparseable,
			wantMsgIn: "where the operation belongs",
		},
		{
			name:   "one separator is below the threshold for claiming to be an audit line",
			line:   `[2026/09/23 22:02:29.216096,  0]   read|write access denied`,
			wantOK: false,
		},
		{
			name:   "an empty line is not an event",
			line:   ``,
			wantOK: false,
		},
		{
			name:   "an unterminated debug header is not an event",
			line:   `[2026/09/23 22:02:29.216096,  1   root|172.21.0.3|public|close|ok|/x`,
			wantOK: false,
		},
		{
			name:   "a line that does not start with the header is not an event",
			line:   `root|172.21.0.3|public|close|ok|/srv/shares/public/x`,
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Parse([]byte(tc.line))
			if ok != tc.wantOK {
				t.Fatalf("Parse ok = %v, want %v (event %+v)", ok, tc.wantOK, got)
			}
			if !tc.wantOK {
				if got != (Event{}) {
					t.Fatalf("Parse returned ok=false with a non-zero event: %+v", got)
				}
				return
			}
			if got.Kind != tc.wantKind {
				t.Errorf("Kind = %v (%q), want %v (%q)", got.Kind, got.Kind.Wording(), tc.wantKind, tc.wantKind.Wording())
			}
			if got.User != tc.wantUser {
				t.Errorf("User = %q, want %q", got.User, tc.wantUser)
			}
			if got.SourceIP != tc.wantIP {
				t.Errorf("SourceIP = %q, want %q", got.SourceIP, tc.wantIP)
			}
			if got.Share != tc.wantShare {
				t.Errorf("Share = %q, want %q", got.Share, tc.wantShare)
			}
			if got.Operation != tc.wantOp {
				t.Errorf("Operation = %q, want %q", got.Operation, tc.wantOp)
			}
			if got.Result != tc.wantRes {
				t.Errorf("Result = %q, want %q", got.Result, tc.wantRes)
			}
			if got.Path != tc.wantPath {
				t.Errorf("Path = %q, want %q", got.Path, tc.wantPath)
			}
			if tc.wantMsgIn != "" && !strings.Contains(got.Message, tc.wantMsgIn) {
				t.Errorf("Message = %q, want it to contain %q", got.Message, tc.wantMsgIn)
			}
		})
	}
}

// TestParseNeverReportsTheFlagAsAPath is the regression #78's note asks
// for by name: the shifted openat line must never produce an event whose
// path is the "r"/"w" flag. Stated separately from the table because it is
// the one wrong answer that would look like a working alert.
func TestParseNeverReportsTheFlagAsAPath(t *testing.T) {
	for _, flag := range []string{"r", "w"} {
		line := `[2026/09/23 22:02:29.216096,  1]   root|172.21.0.3|public|openat|ok|` + flag + `|/srv/shares/public/IT/vpn-setup.pdf`
		got, ok := Parse([]byte(line))
		if !ok {
			t.Fatalf("flag %q: Parse returned no event at all; the line must be reported", flag)
		}
		if got.Kind != KindUnparseable {
			t.Fatalf("flag %q: Kind = %q, want an unparseable-line event", flag, got.Kind.Wording())
		}
		if got.Path == flag {
			t.Fatalf("flag %q: the flag was reported as the path", flag)
		}
		if got.Path != "" {
			t.Fatalf("flag %q: an unparseable line must carry no path, got %q", flag, got.Path)
		}
	}
}

func TestParseBoundsEveryField(t *testing.T) {
	long := strings.Repeat("a", MaxPathLen*2)
	line := `[2026/09/23 22:02:29.216096,  1]   ` + long + `|172.21.0.3|` + long + `|close|ok|/srv/` + long
	got, ok := Parse([]byte(line))
	if !ok || got.Kind != KindAccess {
		t.Fatalf("Parse ok=%v kind=%q, want an access event", ok, got.Kind.Wording())
	}
	if len(got.User) > MaxFieldLen+3 {
		t.Errorf("User is %d bytes, over the %d cap", len(got.User), MaxFieldLen)
	}
	if len(got.Share) > MaxFieldLen+3 {
		t.Errorf("Share is %d bytes, over the %d cap", len(got.Share), MaxFieldLen)
	}
	if len(got.Path) > MaxPathLen+3 {
		t.Errorf("Path is %d bytes, over the %d cap", len(got.Path), MaxPathLen)
	}
	if !strings.HasSuffix(got.Path, "...") {
		t.Errorf("a shortened path must be marked as shortened, got %q", got.Path[len(got.Path)-8:])
	}
}

func TestParseBoundsAPanicMessage(t *testing.T) {
	line := `[2026/09/23 22:06:57.659891,  0]   PANIC (pid 1): ` + strings.Repeat("x", MaxMessageLen*2)
	got, ok := Parse([]byte(line))
	if !ok || got.Kind != KindPanic {
		t.Fatalf("Parse ok=%v kind=%q, want a panic event", ok, got.Kind.Wording())
	}
	if len(got.Message) > MaxMessageLen+3 {
		t.Errorf("Message is %d bytes, over the %d cap", len(got.Message), MaxMessageLen)
	}
}

// TestParseDoesNotModifyItsInput: the caller hands over the tailer's own
// read buffer, so every string in the Event has to be a copy.
func TestParseDoesNotModifyItsInput(t *testing.T) {
	line := []byte(`[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/x`)
	before := string(line)
	ev, ok := Parse(line)
	if !ok {
		t.Fatal("Parse returned no event")
	}
	for i := range line {
		line[i] = 'z'
	}
	if ev.Path != "/srv/shares/public/x" {
		t.Errorf("Path changed when the caller reused its buffer: %q", ev.Path)
	}
	if string(line) == before {
		t.Fatal("test bug: the buffer was not actually overwritten")
	}
}

func TestKindWording(t *testing.T) {
	// The wording is what an operator reads, so a change to any of these
	// strings is a change to the product and should be a deliberate one.
	want := map[Kind]string{
		KindNone:                "",
		KindAccess:              "file access",
		KindUnexpectedOperation: "unexpected operation",
		KindUnparseable:         "unparseable audit line",
		KindPanic:               "server panic",
	}
	for kind, wording := range want {
		if got := kind.Wording(); got != wording {
			t.Errorf("Kind(%d).Wording() = %q, want %q", kind, got, wording)
		}
	}
	if got := Kind(99).Wording(); got != "" {
		t.Errorf("an unknown Kind must have no wording, got %q", got)
	}
}

func TestParseReadsTheLineTimestamp(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "captured audit line",
			line: `[2026/09/23 22:01:53.987124,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/x`,
			want: "2026-09-23 22:01:53.987124",
		},
		{
			name: "captured panic line",
			line: `[2026/09/23 22:06:57.659891,  0]   PANIC (pid 1): sys_setgroups failed in 4.23.8`,
			want: "2026-09-23 22:06:57.659891",
		},
		{
			name: "a header whose timestamp is not a timestamp carries none",
			line: `[not a date,  1]   root|172.21.0.3|public|close|ok|/srv/shares/public/x`,
			want: "",
		},
		{
			name: "a header with no debug level still yields its timestamp",
			line: `[2026/09/23 22:01:53.987124]   root|172.21.0.3|public|close|ok|/srv/shares/public/x`,
			want: "2026-09-23 22:01:53.987124",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Parse([]byte(tc.line))
			if !ok {
				t.Fatal("Parse returned no event")
			}
			if got.Timestamp != tc.want {
				t.Errorf("Timestamp = %q, want %q", got.Timestamp, tc.want)
			}
		})
	}
}
