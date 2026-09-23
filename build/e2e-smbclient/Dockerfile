# A CI-only image holding one thing: a real smbclient, so scripts/e2e/
# smb-lure.sh can drive the shipped SMB lure the way an intruder would.
#
#     docker build -f build/e2e-smbclient/Dockerfile -t e2e-smbclient .
#
# It is separate from build/e2e-samba (which is a whole Debian Samba
# *server*, built to prove the front half of #78's journey) for two
# reasons: this journey needs a client and not a second server, and the
# lure it points at deliberately ships no client tools -- fewer binaries
# in the one container built to be attacked. A Debian server image is
# about ten times the size of this for the one binary actually wanted.
#
# Never anywhere near build/smb-lure or build/mockingbird (ADR-0008). It
# is a client this harness runs, not part of any product image.
FROM alpine:3.24

# Pinned to the same Samba version build/smb-lure/Dockerfile pins its
# server to, from the same Alpine release, so the client and server in
# this journey are never a version apart -- and so a bump to one is a
# visible prompt to bump the other.
RUN apk add --no-cache samba-client=4.23.8-r0

ENTRYPOINT ["smbclient"]
