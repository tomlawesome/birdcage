package tlsconfig

import "testing"

func TestSelect(t *testing.T) {
	tests := []struct {
		name            string
		addr, cert, key string
		wantMode        Mode
		wantAddr        string
		wantUnixPath    string
		wantErr         bool
	}{
		{
			name:     "cert and key set serves HTTPS on the configured address",
			addr:     ":8080",
			cert:     "/etc/birdcage/tls/cert.pem",
			key:      "/etc/birdcage/tls/key.pem",
			wantMode: ModeCert,
			wantAddr: ":8080",
		},
		{
			name:     "cert and key set overrides a non-loopback host too",
			addr:     "0.0.0.0:8080",
			cert:     "/etc/birdcage/tls/cert.pem",
			key:      "/etc/birdcage/tls/key.pem",
			wantMode: ModeCert,
			wantAddr: "0.0.0.0:8080",
		},
		{
			name:    "cert set without key is a refusal",
			addr:    "127.0.0.1:8080",
			cert:    "/etc/birdcage/tls/cert.pem",
			wantErr: true,
		},
		{
			name:    "key set without cert is a refusal",
			addr:    "127.0.0.1:8080",
			key:     "/etc/birdcage/tls/key.pem",
			wantErr: true,
		},
		{
			name:     "loopback IPv4 with no certificate is plain HTTP",
			addr:     "127.0.0.1:8080",
			wantMode: ModePlainLoopbackTCP,
			wantAddr: "127.0.0.1:8080",
		},
		{
			name:     "loopback IPv6 with no certificate is plain HTTP",
			addr:     "[::1]:8080",
			wantMode: ModePlainLoopbackTCP,
			wantAddr: "[::1]:8080",
		},
		{
			name:     "localhost with no certificate is plain HTTP",
			addr:     "localhost:8080",
			wantMode: ModePlainLoopbackTCP,
			wantAddr: "localhost:8080",
		},
		{
			name:         "unix socket with no certificate is plain HTTP",
			addr:         "unix:///run/birdcage/http.sock",
			wantMode:     ModePlainUnixSocket,
			wantUnixPath: "/run/birdcage/http.sock",
		},
		{
			name:    "unix socket with a relative path is a refusal",
			addr:    "unix://relative/http.sock",
			wantErr: true,
		},
		{
			name:     "the documented default address with no certificate mints its own",
			addr:     ":8080",
			wantMode: ModeMintedCert,
			wantAddr: ":8080",
		},
		{
			name:     "0.0.0.0 with no certificate mints its own",
			addr:     "0.0.0.0:8080",
			wantMode: ModeMintedCert,
			wantAddr: "0.0.0.0:8080",
		},
		{
			name:     "a real hostname with no certificate mints its own",
			addr:     "dashboard.example.com:8080",
			wantMode: ModeMintedCert,
			wantAddr: "dashboard.example.com:8080",
		},
		{
			name:     "a LAN IP with no certificate mints its own",
			addr:     "192.168.1.5:8080",
			wantMode: ModeMintedCert,
			wantAddr: "192.168.1.5:8080",
		},
		{
			name:     "a non-loopback IPv6 address with no certificate mints its own",
			addr:     "[2001:db8::1]:8080",
			wantMode: ModeMintedCert,
			wantAddr: "[2001:db8::1]:8080",
		},
		{
			name:    "an address with no port at all is a refusal, not a guess at minting",
			addr:    "127.0.0.1",
			wantErr: true,
		},
		{
			name:    "empty address is a refusal, not a guess at minting",
			addr:    "",
			wantErr: true,
		},
		{
			name:     "cert and key set still wins over minting on a non-loopback host",
			addr:     "dashboard.example.com:8080",
			cert:     "/etc/birdcage/tls/cert.pem",
			key:      "/etc/birdcage/tls/key.pem",
			wantMode: ModeCert,
			wantAddr: "dashboard.example.com:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Select(tt.addr, tt.cert, tt.key)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Select(%q, %q, %q) = %+v, nil; want a refusal error", tt.addr, tt.cert, tt.key, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Select(%q, %q, %q): %v", tt.addr, tt.cert, tt.key, err)
			}
			if got.Mode != tt.wantMode {
				t.Errorf("Mode = %v, want %v", got.Mode, tt.wantMode)
			}
			if got.Addr != tt.wantAddr {
				t.Errorf("Addr = %q, want %q", got.Addr, tt.wantAddr)
			}
			if got.UnixPath != tt.wantUnixPath {
				t.Errorf("UnixPath = %q, want %q", got.UnixPath, tt.wantUnixPath)
			}
		})
	}
}
