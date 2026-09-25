#!/bin/sh
# entrypoint.sh -- binds unbound to this container's own address on the
# stack network, lets only that network ask it anything, checks the
# configuration and execs unbound in the foreground.
#
# Mounts (scripts/e2e/mail-stack.sh makes it):
#   /dns   dkim.conf, the one local-data line publishing the DKIM key,
#          written by `e2e-dkim-sign keygen`. Read-only here: this
#          container never sees the private half, which is in a
#          separate volume only the signer mounts.
set -eu

log() { echo "e2e-dns: $*"; }
die() { echo "e2e-dns: $*" >&2; exit 1; }

[ -s /dns/dkim.conf ] || die "/dns/dkim.conf is missing or empty -- nothing to publish"

# eth0's address with its prefix length, e.g. 172.18.0.5/16. unbound
# listens on the address alone -- not 0.0.0.0 -- and answers only the
# subnet it is on; everything else is refused before it is read.
cidr="$(ip -o -4 addr show dev eth0 | awk '{print $4; exit}')"
[ -n "$cidr" ] || die "eth0 has no IPv4 address"
mkdir -p /run/unbound
cat > /run/unbound/listen.conf <<EOF
	interface: ${cidr%/*}
	access-control: 0.0.0.0/0 refuse
	access-control: ::/0 refuse
	access-control: $cidr allow
EOF
log "listening on ${cidr%/*}:53, answering $cidr only"

unbound-checkconf /etc/unbound/unbound.conf >/dev/null || die "unbound-checkconf refused the configuration"
exec unbound -d -c /etc/unbound/unbound.conf
