package poisoner

import "testing"

// TestParseProfile covers the three values decision 41 settled and the
// refusal that matters: an unrecognised profile is an error, not a silent
// fall back to the default, because the difference between the profiles is
// what the segment sees.
func TestParseProfile(t *testing.T) {
	tests := []struct {
		raw     string
		want    Profile
		wantErr bool
	}{
		{raw: "", want: DefaultProfile},
		{raw: "windows", want: ProfileWindows},
		{raw: "linux", want: ProfileLinux},
		{raw: "off", want: ProfileOff},
		{raw: "Windows", wantErr: true},
		{raw: "win", wantErr: true},
		{raw: "none", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			got, err := ParseProfile(tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want an error: %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
	if DefaultProfile != ProfileWindows {
		t.Errorf("DefaultProfile = %q, want %q (decision 41)", DefaultProfile, ProfileWindows)
	}
}

// TestProfileProtocolSets is decision 41's substance and one of issue #86's
// own "Done when" lines: the linux profile sends what a Linux host sends and
// no NBT-NS, and the off profile sends nothing at all.
func TestProfileProtocolSets(t *testing.T) {
	tests := []struct {
		profile Profile
		want    []Protocol
		sends   bool
	}{
		{profile: ProfileWindows, want: []Protocol{ProtocolLLMNR, ProtocolNBNS, ProtocolMDNS}, sends: true},
		{profile: ProfileLinux, want: []Protocol{ProtocolLLMNR, ProtocolMDNS}, sends: true},
		{profile: ProfileOff, want: nil, sends: false},
	}
	for _, tc := range tests {
		t.Run(string(tc.profile), func(t *testing.T) {
			got := tc.profile.Shape().Protocols
			if len(got) != len(tc.want) {
				t.Fatalf("protocols = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("protocol %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
			if tc.profile.Sends() != tc.sends {
				t.Errorf("Sends() = %v, want %v", tc.profile.Sends(), tc.sends)
			}
			for _, proto := range []Protocol{ProtocolLLMNR, ProtocolNBNS, ProtocolMDNS} {
				want := false
				for _, have := range tc.want {
					if have == proto {
						want = true
					}
				}
				if tc.profile.Asks(proto) != want {
					t.Errorf("Asks(%q) = %v, want %v", proto, tc.profile.Asks(proto), want)
				}
			}
		})
	}

	// The one thing the issue calls out by name.
	if ProfileLinux.Asks(ProtocolNBNS) {
		t.Error("the linux profile asks on NBT-NS, which a Linux host does not speak")
	}
}

// TestProfileShapesDifferWhereTheyShould proves the profile changes the
// shape as well as the protocol set -- otherwise a "linux" canary would be a
// Windows client that happens to send two protocols.
func TestProfileShapesDifferWhereTheyShould(t *testing.T) {
	windows, linux := ProfileWindows.Shape(), ProfileLinux.Shape()

	// RFC 6762 section 5.4's QU bit: a systemd-resolved one-shot lookup
	// asks for a unicast reply, Windows' own resolution does not.
	if windows.MDNSUnicastResponse {
		t.Error("the windows shape sets the mDNS unicast-response bit")
	}
	if !linux.MDNSUnicastResponse {
		t.Error("the linux shape does not set the mDNS unicast-response bit")
	}
	if windows.MDNSTries == linux.MDNSTries {
		t.Errorf("both shapes send %d mDNS tries: the shapes are not actually different", windows.MDNSTries)
	}

	// Every protocol a shape asks on must have a try count, or the lookup
	// would build a datagram and never send it.
	for _, profile := range []Profile{ProfileWindows, ProfileLinux} {
		shape := profile.Shape()
		for _, proto := range shape.Protocols {
			count, gap := tries(proto, shape)
			if count < 1 {
				t.Errorf("%s asks on %s but sends it %d times", profile, proto, count)
			}
			if count > 1 && gap <= 0 {
				t.Errorf("%s retries %s with a gap of %v", profile, proto, gap)
			}
		}
	}
	// And the off profile has nothing to send, so nothing to time.
	if off := ProfileOff.Shape(); len(off.Protocols) != 0 {
		t.Errorf("the off shape asks on %v", off.Protocols)
	}
}

// TestShapeRetriesMatchTheSpecifications pins the counts and gaps to the
// clauses they came from, so a change to any of them is a deliberate one.
func TestShapeRetriesMatchTheSpecifications(t *testing.T) {
	shape := ProfileWindows.Shape()
	// RFC 4795 section 2.4: LLMNR is retransmitted, at a 100 ms timeout.
	if shape.LLMNRTries != 2 || shape.LLMNRRetryGap != llmnrRetryGap {
		t.Errorf("LLMNR = %d tries %v apart, want 2 tries 100ms apart (RFC 4795 2.4)", shape.LLMNRTries, shape.LLMNRRetryGap)
	}
	// RFC 1002 section 4.2.12's BCAST_REQ_RETRY_COUNT is 3; the gap is the
	// ~750 ms issue #86's research note took from a capture.
	if shape.NBNSTries != 3 || shape.NBNSRetryGap != nbnsRetryGap {
		t.Errorf("NBT-NS = %d tries %v apart, want 3 tries 750ms apart", shape.NBNSTries, shape.NBNSRetryGap)
	}
}

// TestWireConstantsMatchTheSpecifications pins the addresses, ports and TTLs
// that a responder actually checks. Two of the three TTLs are the difference
// between being answered and being ignored, not just between looking right
// and looking wrong.
func TestWireConstantsMatchTheSpecifications(t *testing.T) {
	if LLMNRPort != 5355 || MDNSPort != 5353 || NBNSPort != 137 {
		t.Errorf("ports = %d/%d/%d, want 5355/5353/137", LLMNRPort, MDNSPort, NBNSPort)
	}
	if got := llmnrGroupV4.String(); got != "224.0.0.252" {
		t.Errorf("LLMNR IPv4 group = %s, want 224.0.0.252 (RFC 4795 2)", got)
	}
	if got := llmnrGroupV6.String(); got != "ff02::1:3" {
		t.Errorf("LLMNR IPv6 group = %s, want ff02::1:3 (RFC 4795 2)", got)
	}
	if got := mdnsGroupV4.String(); got != "224.0.0.251" {
		t.Errorf("mDNS IPv4 group = %s, want 224.0.0.251 (RFC 6762 3)", got)
	}
	if got := mdnsGroupV6.String(); got != "ff02::fb" {
		t.Errorf("mDNS IPv6 group = %s, want ff02::fb (RFC 6762 3)", got)
	}
	// RFC 4795 section 2.5 requires TTL 1 and requires a responder to
	// discard anything else.
	if llmnrMulticastTTL != 1 {
		t.Errorf("LLMNR multicast TTL = %d, want 1 (RFC 4795 2.5)", llmnrMulticastTTL)
	}
	// RFC 6762 section 11 requires 255 and requires a receiver to check it.
	if mdnsMulticastTTL != 255 {
		t.Errorf("mDNS multicast TTL = %d, want 255 (RFC 6762 11)", mdnsMulticastTTL)
	}
	// A Windows host's own default initial TTL, from issue #86's research
	// note. Not 64, which is the Linux default and one of the giveaways the
	// note lists.
	if nbnsBroadcastTTL != 128 {
		t.Errorf("NBT-NS broadcast TTL = %d, want 128", nbnsBroadcastTTL)
	}
}
