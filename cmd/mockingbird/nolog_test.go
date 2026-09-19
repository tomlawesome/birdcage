package main

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

	"github.com/tomlawesome/birdcage/internal/logging"
)

// This file is #71's regression test for cmd/mockingbird's own package
// doc comment (main.go): the token, any certificate's path or content,
// the receiver's listen address, the log path and the state directory
// must never appear in this agent's log output, at any level. Every
// sub-test here builds a fake Config with distinctive, known-secret
// values (see config_test.go's writeStateDir/setValidEnv for the same
// pattern this package's other tests already use) and proves none of
// them survive into what actually gets logged or returned as an error
// string -- the two places a value could leak into an operator's
// terminal or a log collector.

// genSelfSignedKeyPair returns a freshly generated ECDSA private key's
// PEM bytes alongside a self-signed certificate PEM for it -- enough
// for client.New to accept as both CACert (any parseable certificate)
// and a matched ClientCert/ClientKey pair (tls.X509KeyPair only checks
// the public/private key match, not that the cert is CA-signed).
func genSelfSignedKeyPair(t *testing.T, commonName string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// fakeConfig builds a Config whose every value is distinctive enough
// that its accidental appearance in log output could not be mistaken
// for anything else -- StateDir and LogPath come from t.TempDir(),
// already unique per test, and the token/cert material is freshly
// generated per call.
func fakeConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()

	caCert, _ := genSelfSignedKeyPair(t, "nolog-test-ca")
	clientCert, clientKey := genSelfSignedKeyPair(t, "nolog-test-client")

	token := "sentinel-token-do-not-log-9f8e7d6c5b4a3210"
	tokenPath := filepath.Join(dir, tokenFileName)
	if err := os.WriteFile(tokenPath, []byte(token), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	return Config{
		BirdcageURL:  "https://birdcage.invalid:8443",
		StateDir:     dir,
		LogPath:      filepath.Join(dir, "opencanary.json"),
		Listen:       "127.0.0.1:0",
		CACert:       caCert,
		ClientCert:   clientCert,
		ClientKey:    clientKey,
		TokenPath:    tokenPath,
		PositionPath: filepath.Join(dir, positionFileName),
	}
}

// TestBootNeverLogsSensitiveValues runs boot -- the startup path main
// runs before entering its blocking service loops (client, token store,
// intake, then the "started" log line) -- against a fake config, and
// proves none of #71's never-log values reach stdout: not the token
// content, not either certificate's PEM bytes, not the log path or
// state directory, and not the receiver's own bound listen address
// (read back from the real *Intake boot returns, since cfg.Listen's
// "127.0.0.1:0" itself is too generic a string to prove anything).
func TestBootNeverLogsSensitiveValues(t *testing.T) {
	cfg := fakeConfig(t)

	var in *Intake
	var bootErr error
	out := captureStdout(t, func() {
		_, _, in, bootErr = boot(cfg, "9.9.9", logging.New("test"))
	})
	t.Cleanup(func() {
		if in != nil {
			_ = in.Receiver.Close()
		}
	})
	if bootErr != nil {
		t.Fatalf("boot: %v", bootErr)
	}

	if !strings.Contains(out, "started") {
		t.Fatalf("captured output = %q, want it to contain the startup line", out)
	}

	boundAddr := in.Receiver.Addr().String()
	never := map[string]string{
		"token":               "sentinel-token-do-not-log-9f8e7d6c5b4a3210",
		"CA cert PEM":         string(cfg.CACert),
		"client cert PEM":     string(cfg.ClientCert),
		"client key PEM":      string(cfg.ClientKey),
		"log path":            cfg.LogPath,
		"state directory":     cfg.StateDir,
		"receiver bound addr": boundAddr,
		"token path":          cfg.TokenPath,
		"position path":       cfg.PositionPath,
	}
	for name, secret := range never {
		if strings.Contains(out, secret) {
			t.Errorf("captured output contains the %s (%q) -- must never be logged:\n%s", name, secret, out)
		}
	}
}

// TestLoadConfigErrorNeverLeaksStateDirPath is config.go's own half of
// the same guarantee: an unreadable state-dir file is a startup failure
// (see config_test.go's TestLoadConfigMissingCACert), and the error
// that produces must name the file by its bare name only, never by the
// real path underneath it -- safeErr (safelog.go) is what strips that.
func TestLoadConfigErrorNeverLeaksStateDirPath(t *testing.T) {
	dir := writeStateDir(t)
	if err := os.Remove(filepath.Join(dir, caFileName)); err != nil {
		t.Fatalf("remove %s: %v", caFileName, err)
	}
	setValidEnv(t, dir)

	_, err := loadConfig()
	if err == nil {
		t.Fatal("loadConfig succeeded with ca.pem missing")
	}
	if strings.Contains(err.Error(), dir) {
		t.Fatalf("loadConfig error = %q, leaks the state directory path %q", err, dir)
	}
	if !strings.Contains(err.Error(), caFileName) {
		t.Fatalf("loadConfig error = %q, want it to still name %s", err, caFileName)
	}
}

// TestLoadTokenStoreErrorNeverLeaksStateDirPath is loadTokenStore's own
// version of the same guarantee, for the token file specifically.
func TestLoadTokenStoreErrorNeverLeaksStateDirPath(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, tokenFileName)

	_, err := loadTokenStore(tokenPath)
	if err == nil {
		t.Fatal("loadTokenStore succeeded with no token file present")
	}
	if strings.Contains(err.Error(), dir) {
		t.Fatalf("loadTokenStore error = %q, leaks the state directory path %q", err, dir)
	}
}
