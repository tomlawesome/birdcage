# A CI-only SNMP client image: a real net-snmp snmpget, built from
# Debian packages on the same base image the rest of this repository
# uses. It exists only to drive issue #88's live check -- a real SNMP
# client against the agent's own UDP listener (internal/agent/snmp) --
# and it is never anywhere near build/mockingbird/Dockerfile (that
# image never gains a client, and #85 keeps scapy and its dependents
# out of it entirely). scripts/e2e/snmp.sh is what runs this, on
# demand, for its own journey.
#
#     docker build -f build/e2e-snmp/Dockerfile -t e2e-snmp .
#
# No server, no entrypoint: unlike build/e2e-samba (which stands up a
# real smbd), the thing under test here is the canary container itself
# -- this image only ever runs `snmpget` against it.
FROM debian:trixie-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       snmp \
    && rm -rf /var/lib/apt/lists/*
