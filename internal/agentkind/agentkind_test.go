package agentkind

import "testing"

func TestHoneypotIsValid(t *testing.T) {
	if !Valid(Honeypot) {
		t.Fatal("Valid(Honeypot) = false, want true")
	}
}

func TestUnknownKindIsInvalid(t *testing.T) {
	if Valid(Kind("seagull")) {
		t.Fatal("Valid(\"seagull\") = true, want false")
	}
	if Valid(Kind("")) {
		t.Fatal(`Valid("") = true, want false`)
	}
}

func TestLookupHoneypot(t *testing.T) {
	p, ok := Lookup(Honeypot)
	if !ok {
		t.Fatal("Lookup(Honeypot) ok = false, want true")
	}
	if p.Ports != "21,22,23,69,80,1433,3306,3389,5060,6379" {
		t.Errorf("Ports = %q, want the fixed mockingbird port list", p.Ports)
	}
	if p.DefaultImage != "mockingbird:latest" {
		t.Errorf("DefaultImage = %q, want %q", p.DefaultImage, "mockingbird:latest")
	}
	if p.ImageEnv != "MOCKINGBIRD_IMAGE" {
		t.Errorf("ImageEnv = %q, want %q", p.ImageEnv, "MOCKINGBIRD_IMAGE")
	}
}

func TestLookupUnknownKind(t *testing.T) {
	p, ok := Lookup(Kind("seagull"))
	if ok {
		t.Fatal("Lookup(\"seagull\") ok = true, want false")
	}
	if p != (Profile{}) {
		t.Errorf("Lookup(\"seagull\") profile = %+v, want zero value", p)
	}
}

func TestKindsIncludesHoneypot(t *testing.T) {
	ks := Kinds()
	if len(ks) == 0 {
		t.Fatal("Kinds() is empty")
	}
	found := false
	for _, k := range ks {
		if k == Honeypot {
			found = true
		}
		if !Valid(k) {
			t.Errorf("Kinds() returned %q, which Valid rejects", k)
		}
	}
	if !found {
		t.Error("Kinds() does not include Honeypot")
	}
}
