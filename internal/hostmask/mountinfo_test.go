package hostmask

import (
	"strings"
	"testing"
)

func TestParseMountinfoBasic(t *testing.T) {
	// A real line shape (proc(5)), root bind plus a covered directory
	// and a covered single file, exactly what Nightjar's own container
	// produces under the ratified run command.
	data := `1 0 8:1 / /host ro,relatime shared:1 - ext4 /dev/root rw
2 1 0:20 / /host/home ro,relatime shared:2 - tmpfs tmpfs ro
3 1 0:21 / /host/etc/shadow ro,relatime shared:3 - tmpfs tmpfs ro
`
	mounts, err := ParseMountinfo(strings.NewReader(data))
	if err != nil {
		t.Fatalf("ParseMountinfo: %v", err)
	}
	if len(mounts) != 3 {
		t.Fatalf("len(mounts) = %d, want 3", len(mounts))
	}
	want := []Mount{
		{MountPoint: "/host", ReadOnly: true},
		{MountPoint: "/host/home", ReadOnly: true},
		{MountPoint: "/host/etc/shadow", ReadOnly: true},
	}
	for i, w := range want {
		if mounts[i] != w {
			t.Errorf("mounts[%d] = %+v, want %+v", i, mounts[i], w)
		}
	}
}

func TestParseMountinfoReadWrite(t *testing.T) {
	data := `1 0 8:1 / /host rw,relatime shared:1 - ext4 /dev/root rw
`
	mounts, err := ParseMountinfo(strings.NewReader(data))
	if err != nil {
		t.Fatalf("ParseMountinfo: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("len(mounts) = %d, want 1", len(mounts))
	}
	if mounts[0].ReadOnly {
		t.Error("ReadOnly = true, want false for an rw mount")
	}
}

func TestParseMountinfoEscapedPath(t *testing.T) {
	// A mount point containing a space is octal-escaped by the kernel as
	// \040 -- not a path any mask here has, but the parser must not
	// silently mis-split the line either.
	data := `1 0 8:1 / /host/weird\040path ro,relatime shared:1 - tmpfs tmpfs ro
`
	mounts, err := ParseMountinfo(strings.NewReader(data))
	if err != nil {
		t.Fatalf("ParseMountinfo: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("len(mounts) = %d, want 1", len(mounts))
	}
	if mounts[0].MountPoint != "/host/weird path" {
		t.Errorf("MountPoint = %q, want %q", mounts[0].MountPoint, "/host/weird path")
	}
}

func TestParseMountinfoSkipsShortLines(t *testing.T) {
	data := "too short\n1 0 8:1 / /host ro,relatime shared:1 - ext4 /dev/root rw\n"
	mounts, err := ParseMountinfo(strings.NewReader(data))
	if err != nil {
		t.Fatalf("ParseMountinfo: %v", err)
	}
	if len(mounts) != 1 {
		t.Fatalf("len(mounts) = %d, want 1 (short line skipped)", len(mounts))
	}
}

// fixtureMounts builds the Mount slice a fully-covered, read-only
// Nightjar container would report: the root bind plus one mount per
// Masks entry, all read-only.
func fixtureMounts() []Mount {
	mounts := []Mount{{MountPoint: "/host", ReadOnly: true}}
	for _, m := range Masks {
		mounts = append(mounts, Mount{MountPoint: HostMountPoint(m, "/host"), ReadOnly: true})
	}
	return mounts
}

func existsAll(map[string]bool) func(string) bool {
	return func(string) bool { return true }
}

func TestCheckPasses(t *testing.T) {
	if err := Check("/host", fixtureMounts(), existsAll(nil)); err != nil {
		t.Fatalf("Check() = %v, want nil", err)
	}
}

// TestCheckMissingMaskIsPathThatDoesNotExist proves the "mask over a
// path the host does not have" case is NOT a failure -- issue #108's own
// operational trap and its remedy (drop the flag) depend on this: a
// host with no /etc/ssh must not be refused for lacking a cover over a
// directory it never had.
func TestCheckMissingMaskIsPathThatDoesNotExist(t *testing.T) {
	mounts := fixtureMounts()
	// Drop the /etc/ssh mount from the fixture (host had none, so the
	// operator dropped the flag) but leave every other mount in place.
	filtered := mounts[:0]
	for _, m := range mounts {
		if m.MountPoint == "/host/etc/ssh" {
			continue
		}
		filtered = append(filtered, m)
	}
	exists := func(p string) bool { return p != "/host/etc/ssh" }
	if err := Check("/host", filtered, exists); err != nil {
		t.Fatalf("Check() = %v, want nil (path does not exist on host)", err)
	}
}

// TestCheckUncoveredExistingPathFails is the case the whole agent-side
// check exists to catch: a mask path that DOES exist under /host but has
// no mount covering it -- a run command edited to drop a flag on a host
// that actually has that path.
func TestCheckUncoveredExistingPathFails(t *testing.T) {
	mounts := fixtureMounts()
	filtered := mounts[:0]
	for _, m := range mounts {
		if m.MountPoint == "/host/home" {
			continue
		}
		filtered = append(filtered, m)
	}
	err := Check("/host", filtered, existsAll(nil))
	if err == nil {
		t.Fatal("Check() = nil, want an error for an uncovered existing path")
	}
	cf, ok := err.(*CheckFailure)
	if !ok {
		t.Fatalf("err = %T, want *CheckFailure", err)
	}
	if !cf.NotCovered {
		t.Error("NotCovered = false, want true")
	}
	if cf.Path != "/host/home" {
		t.Errorf("Path = %q, want %q", cf.Path, "/host/home")
	}
}

// TestCheckWritableMountFails is decision 8's older-Docker backstop:
// "ro on a root bind is only recursively read-only on Docker 25+ with
// kernel 5.12+" -- a submount under /host reporting rw must fail the
// check even though the top-level /host bind itself is ro.
func TestCheckWritableMountFails(t *testing.T) {
	mounts := fixtureMounts()
	for i, m := range mounts {
		if m.MountPoint == "/host/home" {
			mounts[i].ReadOnly = false
		}
	}
	err := Check("/host", mounts, existsAll(nil))
	if err == nil {
		t.Fatal("Check() = nil, want an error for a writable mount")
	}
	cf, ok := err.(*CheckFailure)
	if !ok {
		t.Fatalf("err = %T, want *CheckFailure", err)
	}
	if cf.NotCovered {
		t.Error("NotCovered = true, want false (this is the read-only check)")
	}
	if cf.Path != "/host/home" {
		t.Errorf("Path = %q, want %q", cf.Path, "/host/home")
	}
}

// TestCheckWritableRootBindFails proves the read-only check covers the
// root bind itself, not only its submounts.
func TestCheckWritableRootBindFails(t *testing.T) {
	mounts := fixtureMounts()
	mounts[0].ReadOnly = false // /host itself
	err := Check("/host", mounts, existsAll(nil))
	if err == nil {
		t.Fatal("Check() = nil, want an error for a writable root bind")
	}
	cf := err.(*CheckFailure)
	if cf.Path != "/host" {
		t.Errorf("Path = %q, want %q", cf.Path, "/host")
	}
}

// TestCheckIgnoresMountsOutsideRoot proves a writable mount elsewhere in
// the container (e.g. the agent's own state volume, mounted outside
// /host) does not fail the check -- only mounts at or under root matter.
func TestCheckIgnoresMountsOutsideRoot(t *testing.T) {
	mounts := fixtureMounts()
	mounts = append(mounts, Mount{MountPoint: "/var/lib/nightjar", ReadOnly: false})
	if err := Check("/host", mounts, existsAll(nil)); err != nil {
		t.Fatalf("Check() = %v, want nil (state volume is outside root)", err)
	}
}

// TestCheckRootNotMountedFails proves the point-0 guard: a run command
// missing -v /:/host:ro entirely leaves nothing for the other two checks
// to catch (no mask path "exists" under an absent root, no mount is
// found under root to flag as writable), so Check must refuse on the
// missing root mount itself rather than silently passing.
func TestCheckRootNotMountedFails(t *testing.T) {
	err := Check("/host", nil, func(string) bool { return false })
	if err == nil {
		t.Fatal("Check() = nil, want an error when root itself is not mounted")
	}
	cf, ok := err.(*CheckFailure)
	if !ok {
		t.Fatalf("err = %T, want *CheckFailure", err)
	}
	if !cf.RootMissing {
		t.Error("RootMissing = false, want true")
	}
	if cf.Path != "/host" {
		t.Errorf("Path = %q, want %q", cf.Path, "/host")
	}
}

func TestCheckFailureErrorText(t *testing.T) {
	notCovered := &CheckFailure{Path: "/host/home", NotCovered: true}
	if got := notCovered.Error(); !strings.Contains(got, "/host/home") || !strings.Contains(got, "not covered") {
		t.Errorf("Error() = %q, want it to name the path and say not covered", got)
	}
	notReadOnly := &CheckFailure{Path: "/host/home"}
	if got := notReadOnly.Error(); !strings.Contains(got, "/host/home") || !strings.Contains(got, "read-only") {
		t.Errorf("Error() = %q, want it to name the path and say not read-only", got)
	}
}
