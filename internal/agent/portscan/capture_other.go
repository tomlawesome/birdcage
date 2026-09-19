//go:build !linux

package portscan

import "errors"

// captureSocket exists on non-Linux builds only so this package
// compiles there -- `go vet ./...` and an editor's build on a
// developer's machine, not a deployment. AF_PACKET, SO_ATTACH_FILTER
// and CAP_NET_RAW are all Linux, and Mockingbird ships only as a Linux
// container image (ADR-0008 decision 1). Everything worth testing --
// the filter program, the packet parser, the sliding window, the event
// encoding -- is in the platform-independent files and is tested on
// every platform.
type captureSocket struct{}

var errUnsupportedPlatform = errors.New("portscan: packet capture needs Linux (AF_PACKET)")

func openCapture() (*captureSocket, error) { return nil, errUnsupportedPlatform }

func (c *captureSocket) Read([]byte) (int, bool, error) { return 0, false, errUnsupportedPlatform }

func (c *captureSocket) Close() error { return nil }
