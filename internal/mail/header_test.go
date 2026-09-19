package mail

import "testing"

func TestHeaderSafeRejectsEveryControlCharacter(t *testing.T) {
	bad := map[string]string{
		"CR":            "one\rtwo",
		"LF":            "one\ntwo",
		"CRLF":          "one\r\ntwo",
		"NUL":           "one\x00two",
		"tab":           "one\ttwo",
		"DEL":           "one\x7ftwo",
		"C1":            "one\u0085two",
		"escape":        "one\x1b[31mtwo",
		"invalid UTF-8": "one\xfftwo",
	}
	for name, v := range bad {
		if headerSafe(v) {
			t.Errorf("headerSafe(%s) = true, want false", name)
		}
	}

	good := []string{"", "canary-iot", "Birdcage", "café", "日本語", "a b c", "canary — iot"}
	for _, v := range good {
		if !headerSafe(v) {
			t.Errorf("headerSafe(%q) = false, want true", v)
		}
	}
}

func TestStripControlKeepsEverythingElse(t *testing.T) {
	cases := map[string]string{
		"canary-iot":                 "canary-iot",
		"canary\r\nBcc: x@y.invalid": "canaryBcc: x@y.invalid",
		"\x1b[31mred\x1b[0m":         "[31mred[0m",
		"\x00\x01\x02":               "",
		"café":                       "café",
	}
	for in, want := range cases {
		if got := stripControl(in); got != want {
			t.Errorf("stripControl(%q) = %q, want %q", in, got, want)
		}
	}
}
