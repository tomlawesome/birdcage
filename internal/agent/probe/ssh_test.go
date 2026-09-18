package probe

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestProbeSSH_PlantsMarkerAsUsernameAndTreatsRejectionAsSuccess(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	var gotUser string
	serverCfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			gotUser = conn.User()
			return nil, errors.New("rejected: this is a self-test probe, not a real credential")
		},
	}
	serverCfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// An auth failure is the expected outcome; the server
		// connection itself never completes past that.
		_, _, _, _ = ssh.NewServerConn(c, serverCfg)
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probeSSH(ctx, "127.0.0.1", port, "marker-ssh"); err != nil {
		t.Fatalf("probeSSH: want nil for a rejected credential (the expected case), got %v", err)
	}

	<-done
	if gotUser != "marker-ssh" {
		t.Errorf("server saw username %q, want the marker %q", gotUser, "marker-ssh")
	}
}

func TestProbeSSH_DialFailureIsAnError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := probeSSH(ctx, "127.0.0.1", port, "m"); err == nil {
		t.Fatal("probeSSH against a closed port: want an error, got nil")
	}
}
