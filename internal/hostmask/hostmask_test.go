package hostmask

import (
	"reflect"
	"testing"
)

// TestNeverMasked is issue #108's own required test: "Never masked ...
// and a test must assert this: /etc as a whole, /etc/os-release,
// /var/lib/docker. Grype needs /etc/os-release to identify the
// distribution."
func TestNeverMasked(t *testing.T) {
	neverMasked := []string{"/etc", "/etc/os-release", "/var/lib/docker"}
	for _, p := range neverMasked {
		for _, m := range Masks {
			if m.Path == p {
				t.Errorf("%s is in Masks, want it never masked", p)
			}
		}
	}
}

func TestMasksMatchRatifiedList(t *testing.T) {
	wantFiles := []string{"/etc/shadow", "/etc/gshadow"}
	wantDirs := []string{"/etc/ssh", "/root", "/proc", "/run", "/sys", "/dev", "/tmp", "/var/tmp", "/home"}

	var gotFiles, gotDirs []string
	for _, m := range Masks {
		switch m.Kind {
		case File:
			gotFiles = append(gotFiles, m.Path)
		case Dir:
			gotDirs = append(gotDirs, m.Path)
		default:
			t.Errorf("mask %s has unknown Kind %v", m.Path, m.Kind)
		}
		if m.Why == "" {
			t.Errorf("mask %s has no Why", m.Path)
		}
	}
	if !reflect.DeepEqual(gotFiles, wantFiles) {
		t.Errorf("file masks = %v, want %v", gotFiles, wantFiles)
	}
	if !reflect.DeepEqual(gotDirs, wantDirs) {
		t.Errorf("dir masks = %v, want %v", gotDirs, wantDirs)
	}
}

func TestPaths(t *testing.T) {
	paths := Paths()
	if len(paths) != len(Masks) {
		t.Fatalf("len(Paths()) = %d, want %d", len(paths), len(Masks))
	}
	for i, m := range Masks {
		if paths[i] != m.Path {
			t.Errorf("Paths()[%d] = %q, want %q", i, paths[i], m.Path)
		}
	}
}

func TestHostMountPoint(t *testing.T) {
	got := HostMountPoint(Mask{Path: "/etc/shadow"}, "/host")
	if got != "/host/etc/shadow" {
		t.Errorf("HostMountPoint = %q, want %q", got, "/host/etc/shadow")
	}
}

func TestRunFlags(t *testing.T) {
	flags := RunFlags("/host")
	if len(flags) != len(Masks) {
		t.Fatalf("len(RunFlags) = %d, want %d", len(flags), len(Masks))
	}
	want := map[string]bool{
		"-v /dev/null:/host/etc/shadow:ro":  true,
		"-v /dev/null:/host/etc/gshadow:ro": true,
		"--tmpfs /host/etc/ssh:ro":          true,
		"--tmpfs /host/root:ro":             true,
		"--tmpfs /host/proc:ro":             true,
		"--tmpfs /host/run:ro":              true,
		"--tmpfs /host/sys:ro":              true,
		"--tmpfs /host/dev:ro":              true,
		"--tmpfs /host/tmp:ro":              true,
		"--tmpfs /host/var/tmp:ro":          true,
		"--tmpfs /host/home:ro":             true,
	}
	for _, f := range flags {
		if !want[f] {
			t.Errorf("unexpected flag %q", f)
		}
		delete(want, f)
	}
	for f := range want {
		t.Errorf("missing flag %q", f)
	}
}
