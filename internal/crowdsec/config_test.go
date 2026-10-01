package crowdsec

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// selfSignedPEM makes one throwaway certificate so the CA-file tests
// have a real PEM to point at.
func selfSignedPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "throwaway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func getenvFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadNothingSetIsOff(t *testing.T) {
	loaded, err := Load(getenvFrom(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Enabled {
		t.Fatal("Enabled = true with nothing set")
	}
}

func TestLoadHappyPath(t *testing.T) {
	pw := writeFile(t, "pw", "s3cret\n")
	ca := writeFile(t, "ca.pem", selfSignedPEM(t))
	loaded, err := Load(getenvFrom(map[string]string{
		EnvLAPIURL:      "https://lapi.example.test:8080/prefix/",
		EnvMachineID:    "birdcage",
		EnvPasswordFile: pw,
		EnvCAFile:       ca,
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !loaded.Enabled {
		t.Fatal("Enabled = false")
	}
	cfg := loaded.Config
	if cfg.LAPIURL != "https://lapi.example.test:8080/prefix" {
		t.Errorf("LAPIURL = %q, want trailing slash trimmed", cfg.LAPIURL)
	}
	if cfg.MachineID != "birdcage" || cfg.Password != "s3cret" {
		t.Errorf("MachineID/Password = %q/%q", cfg.MachineID, cfg.Password)
	}
	if cfg.RootCAs == nil || cfg.CAFile != ca {
		t.Errorf("RootCAs/CAFile not loaded: %v %q", cfg.RootCAs, cfg.CAFile)
	}
}

func TestLoadSystemRootsWhenNoCAFile(t *testing.T) {
	pw := writeFile(t, "pw", "s3cret")
	loaded, err := Load(getenvFrom(map[string]string{
		EnvLAPIURL: "https://lapi.example.test", EnvMachineID: "birdcage", EnvPasswordFile: pw,
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Config.RootCAs != nil || loaded.Config.CAFile != "" {
		t.Fatal("expected nil RootCAs (system roots) with no CA file")
	}
}

func TestLoadRefusals(t *testing.T) {
	pw := writeFile(t, "pw", "s3cret")
	empty := writeFile(t, "empty", "\n")
	notPEM := writeFile(t, "not.pem", "hello")
	base := func(over map[string]string) map[string]string {
		m := map[string]string{EnvLAPIURL: "https://lapi.example.test", EnvMachineID: "birdcage", EnvPasswordFile: pw}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"half set: only url", map[string]string{EnvLAPIURL: "https://x"}, EnvMachineID + " is not set"},
		{"half set: only password file", map[string]string{EnvPasswordFile: pw}, EnvLAPIURL + " is not set"},
		{"http refused", base(map[string]string{EnvLAPIURL: "http://lapi.example.test:8080"}), "must start with https://"},
		{"no host", base(map[string]string{EnvLAPIURL: "https:///v1"}), "must name a host"},
		{"userinfo refused", base(map[string]string{EnvLAPIURL: "https://user:pw@lapi.example.test"}), "must not carry a username or password"},
		{"query refused", base(map[string]string{EnvLAPIURL: "https://lapi.example.test/?x=1"}), "query string or fragment"},
		{"fragment refused", base(map[string]string{EnvLAPIURL: "https://lapi.example.test/#frag"}), "query string or fragment"},
		{"control char in machine id", base(map[string]string{EnvMachineID: "bird\ncage"}), "control character"},
		{"machine id too long", base(map[string]string{EnvMachineID: strings.Repeat("a", maxMachineIDLen+1)}), "longer than"},
		{"password file missing", base(map[string]string{EnvPasswordFile: filepath.Join(t.TempDir(), "nope")}), "not usable"},
		{"password file empty", base(map[string]string{EnvPasswordFile: empty}), "is empty"},
		{"ca file missing", base(map[string]string{EnvCAFile: filepath.Join(t.TempDir(), "nope.pem")}), EnvCAFile},
		{"ca file not pem", base(map[string]string{EnvCAFile: notPEM}), "holds no PEM certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(getenvFrom(tc.env))
			if err == nil {
				t.Fatal("Load returned no error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "s3cret") {
				t.Fatalf("error leaks the password: %q", err)
			}
		})
	}
}

func TestLoadPasswordWithLineBreakRefused(t *testing.T) {
	pw := writeFile(t, "pw", "s3c\rret\n")
	_, err := Load(getenvFrom(map[string]string{
		EnvLAPIURL: "https://lapi.example.test", EnvMachineID: "birdcage", EnvPasswordFile: pw,
	}))
	if err == nil || !strings.Contains(err.Error(), "control character") {
		t.Fatalf("err = %v, want a control-character refusal", err)
	}
	if strings.Contains(err.Error(), "s3c") {
		t.Fatalf("error leaks the password: %q", err)
	}
}
