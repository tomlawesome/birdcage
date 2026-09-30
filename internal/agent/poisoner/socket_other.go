//go:build !linux

package poisoner

import (
	"errors"
	"net"
	"syscall"
)

// This file exists so the package compiles off Linux -- `go vet ./...` and
// an editor's build on a developer's machine, not a deployment. Mockingbird
// ships only as a Linux container image (ADR-0008 decision 1), and every
// socket option this package needs is Linux's: SO_REUSEADDR sharing of one
// UDP port between a wildcard and a specific bind, IP_ADD_MEMBERSHIP,
// IP_MULTICAST_TTL/LOOP, and the shutdown-on-an-unconnected-socket
// behaviour the package comment describes.
//
// Everything worth testing -- the three encoders, the reply parser, the
// name generator, the pace-matcher, the schedule and the event encoding --
// is in the platform-independent files and is tested on every platform.

var errUnsupportedPlatform = errors.New("poisoner: bait queries need Linux")

func listenReceiveOnly(int, []net.IP) (*net.UDPConn, error) { return nil, errUnsupportedPlatform }

func shutdownWrite(*net.UDPConn) error { return errUnsupportedPlatform }

func controlSetReuseAddr(_, _ string, _ syscall.RawConn) error { return errUnsupportedPlatform }

func joinGroupV4(*net.UDPConn, net.IP) error { return errUnsupportedPlatform }

func setTTLv4(*net.UDPConn, int) error { return errUnsupportedPlatform }

func setMulticastTTLv4(*net.UDPConn, int) error { return errUnsupportedPlatform }

func setMulticastHopsV6(*net.UDPConn, int) error { return errUnsupportedPlatform }
