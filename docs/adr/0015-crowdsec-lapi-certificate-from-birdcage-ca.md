# ADR-0015: Birdcage issues the CrowdSec LAPI's TLS certificate from its own root CA, server-auth only, one year, written once to the LAPI's own storage

**Status:** Proposed (one owner question, below; everything else is decided)
**Date:** 2026-10-02
**Relates to:** #163 (this feature), #4 (CrowdSec integration; owner
answers 2a and 4a, 2026-10-01), #150 (CA rotation; owner ruling
2026-09-30, not yet built), #62 (only the CA key touches the birdcage
host's disk), #47 and #63 (the CA and the certificates it already
mints), ADR-0014 (the LAPI connection this certificate secures),
ADR-0011 (the kind an issued certificate's OU carries).
**Amends:** nothing. ADR-0014 decision 7's trust row gains a third
anchor (birdcage's own CA); its `https://`-only rule is unchanged.

## Context

The LAPI connection is HTTPS-only, including across a private Docker
network (owner, 2026-10-01, answer 4a on #4). Today that means the
operator makes a certificate for the CrowdSec container themselves and
hands birdcage the CA that signed it through
`BIRDCAGE_CROWDSEC_CA_FILE`. Birdcage already runs a certificate
authority (`internal/ca`, `BIRDCAGE_CA_DIR`) that mints the ingest,
enrolment and dashboard serving certificates and every canary's client
certificate. #163 asks birdcage to mint the LAPI's certificate too, so
the operator copies files into the CrowdSec container instead of
running `openssl` by hand. It is a setup convenience, not a security
fix, and the owner decided (2026-10-02) that the design comes from one
session and the build from another; this ADR is the design.

The question the convenience raises is the one this ADR is mostly
about: birdcage's CA is the trust root for the whole canary fleet and
for the dashboard a human logs into. Issuing one more certificate from
it must not widen what a stolen certificate, a stolen key, or a misused
CA lets someone do.

## Research

Read from the authoritative record at the `v1.8.1` tag of
`crowdsecurity/crowdsec` (the version `scripts/e2e/crowdsec-stack.sh`
pins), from Go's `crypto/x509` and `crypto/tls` documentation, and from
the primary pages cited, on 2026-10-02. Paths are relative to the
CrowdSec repository.

### What the official image does with its TLS settings

- `build/docker/docker_start.sh`: with `USE_TLS=true`, `LAPI_CERT_FILE`
  and `LAPI_KEY_FILE` become `api.server.tls.cert_file` / `key_file`.
  **`CACERT_FILE` is written to two places at once:** the local agent's
  credentials file (`.ca_cert_path` in `local_api_credentials.yaml`,
  which is how the container's own `cscli` and log processor verify
  the LAPI's certificate when they dial `LOCAL_API_URL`), *and*
  `api.server.tls.ca_cert_path`. There is no setting that does one
  without the other. With `USE_TLS` unset the script deletes
  `api.server.tls` entirely.
- `pkg/csconfig/tls.go`, `GetTLSConfig`: the server's `ClientAuth`
  defaults to `tls.VerifyClientCertIfGiven` (there is a
  `client_verification` key but the image exposes no variable for it),
  and `ClientCAs` is the system pool plus `ca_cert_path`. `MinVersion`
  is TLS 1.2. The certificate is loaded once by
  `http.Server.ServeTLS` (`pkg/apiserver/apiserver.go`): **no reload on
  file change, so a renewed certificate needs a container restart.**
- `pkg/apiserver/middlewares/v1/tls_auth.go`: a client certificate
  that chains to `ClientCAs` authenticates as a machine or a bouncer
  when its `Subject.OrganizationalUnit` is in `agents_allowed_ou` or
  `bouncers_allowed_ou` (image defaults `agent-ou` and `bouncer-ou`,
  `build/docker/config.yaml`), and `build/docker/README.md` says such
  machines and bouncers "are automatically registered and don't need a
  username or password". CRL and OCSP are checked when configured.
- So **the CA the container is told to trust is also a CA it will
  accept client certificates from.** Handing the official image
  birdcage's `ca.pem` as `CACERT_FILE` -- which is the only way its own
  `cscli` can verify a birdcage-issued LAPI certificate without
  `INSECURE_SKIP_VERIFY=true` -- makes every certificate birdcage's CA
  ever issued a candidate machine or bouncer credential, gated by one
  string comparison on the OU. Birdcage issues exactly two OU values,
  `honeypot` and `scanner` (`internal/agentkind`, ADR-0011), and this
  ADR's leaf carries none; neither equals `agent-ou` or `bouncer-ou`.
  That gap is what keeps a canary's client certificate -- which lives
  on a deliberately exposed box -- from logging into the LAPI, and
  decision 9 below pins it with a test.
- The image's final stage (`build/docker/Dockerfile`, `alpine:3.24`)
  installs only `tzdata bash rsync`: **no `openssl`**, so a flow where
  the key is generated inside the CrowdSec container and birdcage signs
  a request is not available without the operator installing tooling,
  which is the friction #163 exists to remove.
- Container's own LAPI URL: the e2e stack already sets
  `LOCAL_API_URL=https://localhost:8080`; the image's default is
  `http://0.0.0.0:8080`. The LAPI certificate therefore has to cover
  `localhost` or the container's own `cscli` fails verification.

### What Go verifies, and so what a leaf can and cannot be used for

- Server-side verification of a client certificate in `crypto/tls`
  uses `KeyUsages: {ExtKeyUsageClientAuth}`; a leaf with only
  `ExtKeyUsageServerAuth` fails it. Client-side verification of a
  server uses `ExtKeyUsageServerAuth`; a canary's client leaf
  (`clientAuth` only) cannot be served as a server. Both of birdcage's
  verifiers are Go, and so is CrowdSec's.
- A certificate without `IsCA` (and without the basic-constraints
  extension) cannot sign: `x509.Certificate.Verify` rejects an
  intermediate that is not a CA (`CANotAuthorizedToSign`). The leaf
  below sets `BasicConstraintsValid: true, IsCA: false` explicitly so
  non-Go verifiers see the same thing.
- Hostname verification is on SANs only; the CommonName fallback was
  removed in Go 1.15. The names on the leaf are the whole of what it
  can impersonate.
- TLS does not scope a certificate by port. A leaf whose SANs include a
  name birdcage itself serves on -- `BIRDCAGE_ADVERTISE_HOST` for the
  ingest and enrolment listeners, or any name the dashboard's own
  minted certificate covers -- would verify as birdcage to a canary or
  a browser that already trusts birdcage's CA. This is the one way a
  stolen LAPI key reaches past the LAPI, and decision 5 refuses it.

### CVEs and advisories

NVD `keywordSearch=crowdsec`, 2026-10-02: five results, the same two
CrowdSec records ADR-0014 analysed (CVE-2026-44981, CVE-2026-44982;
both server-side, both fixed by 1.7.8, the pin is 1.8.1) and three
unrelated products. Nothing concerns the LAPI's TLS listener, its
client-certificate path, or certificate handling. Go's `crypto/x509`
and `crypto/tls` are covered by `lint:govulncheck` on every pipeline;
no open advisory touches the APIs used here.

### Prior art: secure and insecure

Known-good shapes this design copies:

- **Split extended key usage.** Docker's own daemon-TLS guide
  (`docs.docker.com/engine/security/protect-access/`) writes
  `extendedKeyUsage = serverAuth` into the server's extension file and
  `extendedKeyUsage = clientAuth` into the client's, so neither
  certificate can stand in for the other. `internal/ca` already does
  this for its own leaves; the LAPI leaf keeps to it.
- **One trust root, kept honest by what the leaf says rather than by
  who holds it.** Kubernetes documents the failure the other way round
  (`kubernetes.io/docs/tasks/extend-kubernetes/configure-aggregation-layer/`):
  "Kubernetes and the kube-apiserver have multiple CAs, so make sure
  that the proxy is signed by the aggregation layer CA and not by
  something else, like the Kubernetes general CA", and warns that
  "reusing the same CA for different client types can negatively
  impact the cluster's ability to function" -- a client certificate
  from the general CA would pass the front-proxy check. The lesson is
  not "never share a CA"; it is that when a CA is shared, the
  *verifier* must distinguish the certificate's purpose, by EKU, by
  name, by OU -- never by assuming only the right holder has one. Every
  verifier in play here does (above).
- **Short lives for hand-copied certificates.** The CA/Browser Forum's
  ballot SC-081v3 (passed 2025-04-11) takes public certificate validity
  from 398 days to 47 by March 2029, because "the more time passes from
  that moment of issuance, the more likely it becomes that data
  represented in the certificate diverge from reality". Birdcage's own
  in-memory leaves live 24 hours. A certificate the operator installs
  by hand cannot be that short, but it can be bounded, and the bound is
  what limits a stolen key.
- **The private key is born where it is used, or written once and
  never kept.** #62's rule for the birdcage host, and `cscli`'s own
  `local_api_credentials.yaml` and bouncer configs: root-only files on
  the machine that needs them, never environment variables.

Known-bad shapes this design refuses:

- **`INSECURE_SKIP_VERIFY=true` on the CrowdSec side**, which is what an
  operator reaches for when the container's own `cscli` cannot verify
  the LAPI's certificate. Birdcage writes `ca.pem` next to the leaf so
  `CACERT_FILE` is a copy, not a shrug.
- **A wildcard or birdcage-served name on the LAPI leaf.** Either lets
  one key impersonate more than the LAPI.
- **A leaf that could also be a client.** No `clientAuth`, no OU.
- **A leaf that outlives its root.** `NotAfter` is capped at the CA's.
- **Overwriting a key file silently**, or writing one into the CA
  directory, or keeping a copy anywhere in birdcage.
- **An LAPI certificate from a second CA that then needs installing
  too.** The convenience is that one root already anchors the
  operator's browser and every canary; a second root undoes it.

### What the research changed

- The first sketch had the operator set `CACERT_FILE` only if they
  wanted the container's agent to run. `docker_start.sh` shows `cscli`
  needs it even LAPI-only, and that setting it also enables
  certificate login. That turned "write `ca.pem` too" from a nicety
  into a requirement, and added decision 9's OU guard.
- A sign-a-CSR mode (key never leaves the CrowdSec container) was the
  cleanest fit for #62 and was dropped: the image has no `openssl`,
  and a CA that holds the root key gains nothing by not seeing a leaf
  key.
- `localhost` on the leaf was going to be the operator's choice. The
  image dials it by default; it is always included.
- The leaf's lifetime was going to follow the CA (ten years). The
  CA/B schedule and the stolen-key analysis made it one year.

## Decision

**1. The issuer is birdcage's existing root CA, directly.** Not a
subordinate CA: a persisted intermediate is a second private key on
the birdcage host (what #62 forbids) and a second thing for #150 to
rotate, and an unpersisted one would be re-created on every issuance,
which constrains nothing. Not a separate CA: the point of #163 is that
the one root the operator has already installed anchors this too. What
limits the leaf is the leaf, not the issuer (decisions 2 and 5).

**2. The leaf's profile is fixed; there are no flags for it.** ECDSA
P-256 key, generated in memory. Subject `CN=crowdsec-lapi`, no
organizational unit (so no `agents_allowed_ou`/`bouncers_allowed_ou`
value can ever match it). SANs: `localhost`, `127.0.0.1`, `::1` always
(the container's own `cscli` dials loopback), plus the names the
operator gives. `KeyUsage digitalSignature`; `ExtKeyUsage serverAuth`
only; `BasicConstraints` present and `CA:FALSE`; 128-bit random serial;
`NotBefore` five minutes back for clock skew; chain file is leaf then
CA. This is `IssueServer`'s profile plus the explicit basic
constraints and the lifetime cap, as a new `(*ca.CA).IssueLAPI`.

**3. One year, capped at the CA's expiry.** `NotAfter` is the earlier
of now + 365 days and the CA's own `NotAfter`; when the cap applies,
the command says so. One year because the file is installed by hand
(24 hours is not an option), because 398 days is the most any public
CA may issue today and the figure is falling, and because the validity
window is the only limit on a stolen key -- birdcage has no revocation
for the leaves it issues and this ADR does not add one. When the leaf
expires, `birdcage crowdsec add` fails closed with the TLS error named
and nothing else in birdcage changes: no canary, no dashboard, no
listener depends on this certificate. That is the property #150's
ruling asks for ("rotation must never leave a canary unable to
authenticate") applied here by construction.

**4. The command is `birdcage crowdsec cert --out <dir> <host>...`,
and it writes three files, once.** Into `<dir>`: `lapi.pem` (`0644`,
leaf and CA), `lapi-key.pem` (`0600`), `ca.pem` (`0644`, birdcage's CA
certificate, for `CACERT_FILE`). Each is written to a temp file in the
same directory and renamed into place (the `internal/ca` pattern). If
any of the three already exists the command refuses, naming it, unless
`--replace` is given: a renewal is deliberate, never a side effect.
`<dir>` must exist; it must not be `BIRDCAGE_CA_DIR` or under it (the
CA directory holds exactly two files and nothing else ever goes
there). Birdcage keeps no copy of the key: it is not logged, not
printed, not stored, and the only record of the issuance is the audit
row in decision 8. The intended `<dir>` is the CrowdSec container's
TLS volume, mounted into birdcage for the one command (the
`docs/configuration.md` example is `docker compose run --rm -v
crowdsec-tls:/out birdcage crowdsec cert --out /out crowdsec`); then
the container runs with `USE_TLS=true`, `LAPI_CERT_FILE=/tls/lapi.pem`,
`LAPI_KEY_FILE=/tls/lapi-key.pem`, `CACERT_FILE=/tls/ca.pem`,
`LOCAL_API_URL=https://localhost:8080`. The official image runs as
root, so a `0600` file owned by birdcage's uid is readable there; an
operator running it as another user changes the owner, and the docs
say so. *Why this is within #62, as read here:* #62 is about
birdcage's **own** keys piling up on the birdcage host -- "prefer
never-written over shredded". This key is the LAPI's, not birdcage's;
it has to exist as a file on the LAPI's storage in every possible
design; it is written once, to that storage, at the operator's
explicit instruction, and birdcage holds nothing afterwards. The owner
question at the end asks for that reading to be confirmed, because the
rule's wording is "exactly one private key exists as a file".

**5. Names are validated exactly, and names birdcage serves on are
refused.** Each positional argument is either an IP literal
(`netip.ParseAddr`; no zone, not unspecified, not multicast) or a
hostname: lower-cased, 1--253 characters, labels of 1--63
letters/digits/hyphens with no leading or trailing hyphen, no empty
label, no trailing dot, no `*` anywhere, no underscore. At least one
name; at most 16; duplicates and the always-included loopback names are
collapsed. Refused outright, with the variable named: a name equal to
`BIRDCAGE_ADVERTISE_HOST`, or to any name
`tlsconfig.DashboardHosts(BIRDCAGE_DASHBOARD_HOST)` would put on the
dashboard's certificate (the loopback names excepted). The reason is
the research note above: TLS does not know ports, and a LAPI leaf for
a name birdcage answers on is a birdcage impersonation certificate.
The private-network deployment the owner described reaches the LAPI by
its container name (`https://crowdsec:8080`), which is never a name
birdcage serves, so the refusal costs that deployment nothing. The
residual: loopback is on both certificates. Reaching birdcage over
loopback with a stolen LAPI key means already being on birdcage's own
host or network namespace, where the CA key itself is; named, not
mitigated.

**6. Birdcage always trusts its own CA for the LAPI, in addition to
whatever else is configured.** At startup and before
`birdcage crowdsec add` contacts anything, the trust pool for
`BIRDCAGE_CROWDSEC_LAPI_URL` is built as: `BIRDCAGE_CROWDSEC_CA_FILE`'s
certificates if set, otherwise the system roots; plus birdcage's own
CA certificate if `BIRDCAGE_CA_DIR/ca.pem` exists. Reading `ca.pem`
never creates a CA: a ban must not mint a trust root as a side effect,
so this path reads the public certificate only and treats "no CA yet"
as "no third anchor", logged. `BIRDCAGE_CROWDSEC_CA_FILE` keeps
working unchanged for an operator whose LAPI certificate comes from
their own CA, and setting it alongside a birdcage-issued certificate
is harmless (the same anchor twice, or two anchors). The startup line
names the anchors in words: "TLS verified against birdcage's own CA
(pin=…) and the system roots", or "… and BIRDCAGE_CROWDSEC_CA_FILE=…",
or "the system roots only (birdcage's CA not created yet)". There is
still no skip-verify knob and no `http://`.

**7. Renewal is the same command with `--replace`, then a container
restart; CA rotation (#150) reissues it.** Reissuing does not
invalidate the previous leaf -- it remains valid until its own
`NotAfter`, and the operator removes the old files. The reminders this
ADR provides are the two points where birdcage already has the
operator's attention: the issuing command prints the expiry date, and
every `birdcage crowdsec add` prints a warning on stderr when the
certificate the LAPI actually presented (whoever issued it) has fewer
than 30 days left, or has expired (the add then fails closed with that
reason). #150, when built, gets the LAPI leaf as a second item in its
stacked reminders -- the audit row carries `not_after` -- and its
rotation checklist gains one step: issue a new LAPI leaf from the new
root during the overlap window, while decision 6's pool holds both
roots. Nothing here needs reopening for that; the trust-pool builder
takes a list of anchors from the start.

**8. Audit rows.** `crowdsec.cert_issued` -- target: the operator's
names, comma-joined; reason: `serial=<hex> not_after=<RFC3339>
sans=<every SAN> ca_pin=<CA pin> out=<dir>`; `triggered_by` `cli`.
Written only after all three files are in place. A failure between
minting and the last rename writes `crowdsec.cert_failed` with the
stage and names any file already written, so the operator knows what
to delete. A name refusal, a missing `--out`, or a refused overwrite
writes nothing: nothing was issued. An audit write that fails after the
files exist is an error naming both facts, never silent (ADR-0014's
rule). No `crowdsec.block_*` row changes; the near-expiry warning is
stderr and the log, not a row.

**9. The OU gap is a tested invariant.** A unit test in
`internal/crowdsec` asserts that no `agentkind.Kinds()` value and no
subject the LAPI leaf carries equals `agent-ou` or `bouncer-ou`, with a
comment pointing at `tls_auth.go` and this ADR, so a future kind cannot
quietly become a CrowdSec credential. `docs/configuration.md` tells
the operator never to add a birdcage kind to `AGENTS_ALLOWED_OU` or
`BOUNCERS_ALLOWED_OU`.

**10. Live journey.** `scripts/e2e/crowdsec-stack.sh` runs the main
LAPI on a certificate birdcage issued inside the running birdcage
container (`birdcage crowdsec cert --out /crowdsec-tls <container>`),
with `CACERT_FILE` pointing at the written `ca.pem` and birdcage
started with no `BIRDCAGE_CROWDSEC_CA_FILE`. The throwaway CA the stack
already makes now serves a *second*, otherwise identical LAPI
container, the untrusted one. `scripts/e2e/crowdsec.sh` proves, in
addition to everything ADR-0014 lists: the startup log names
birdcage's own CA as an anchor; the serial the LAPI presents
(`openssl s_client` from the helper container) equals the serial in
the `crowdsec.cert_issued` row, and the presented leaf's SANs include
the container name and `localhost`; `cscli lapi status` inside the
container succeeded over that certificate (that is `lapi_ready`); a
real add lands on it; a second `cert` without `--replace` refuses and
changes no file; a wildcard name, `BIRDCAGE_ADVERTISE_HOST`'s value,
and `--out` inside the CA directory each refuse before anything is
written; the untrusted LAPI fails closed with a certificate reason and
nothing added when `BIRDCAGE_CROWDSEC_CA_FILE` is unset; the same
untrusted LAPI accepts an add when `BIRDCAGE_CROWDSEC_CA_FILE` names
its CA (the operator's-own-CA path still works); and the main LAPI
accepts an add when `BIRDCAGE_CROWDSEC_CA_FILE` names an unrelated CA
(the own-CA anchor is additive). Jobs `e2e:crowdsec` and
`e2e:crowdsec:postgres`, unchanged in placement.

**11. No new module, no new table, no new environment variable.** The
whole of the new code is `crypto/x509`, `crypto/ecdsa`, `encoding/pem`,
`net/netip` and `os`. The record of issuance is `audit_log`.

## Failure modes

| Failure | Behaviour |
| --- | --- |
| No name given, a bad name (wildcard, underscore, zone, unspecified address, too long), more than 16, a name birdcage serves on | Refused with the rule and, where it applies, the variable named; nothing minted, no row. |
| `--out` missing, not a directory, or at or under `BIRDCAGE_CA_DIR` | Refused; nothing minted, no row. |
| A target file exists and `--replace` was not given | Refused, naming the file; nothing written, no row. |
| CA directory missing or wrongly permissioned | `ca.Load`'s refusal, as every CA-using command; nothing written. |
| CA has fewer than 365 days left | Leaf capped at the CA's expiry; the command says so and prints both dates. |
| Write fails after some files landed | `crowdsec.cert_failed` naming the stage and the files present; non-zero exit. |
| Audit write fails after all files landed | Error naming both facts; the files are left (they are correct); non-zero exit. |
| `birdcage crowdsec add` against a leaf with < 30 days left | Warning on stderr naming the date and the renewal command; the add proceeds. |
| Leaf expired, or not issued by any configured anchor, or name mismatch | `crowdsec.block_failed` with the TLS reason; nothing added; the fleet is unaffected. |
| `BIRDCAGE_CA_DIR/ca.pem` absent at `add` time | The pool is the system roots or `BIRDCAGE_CROWDSEC_CA_FILE`; logged as such; a birdcage-issued leaf cannot exist yet, so nothing is lost. |
| Operator sets `BIRDCAGE_CROWDSEC_CA_FILE` as well | Both anchors; works. |
| Operator points `CACERT_FILE` at the wrong file | The container's own `cscli` fails verification and says so; birdcage is unaffected. |

## Out of scope

- Revocation of an issued leaf, or pinning `add` to the most recently
  issued serial so that reissue revokes. Pinning would turn
  `audit_log` into state and would fail closed after a database
  restore from before the last issuance; the one-year life is the
  bound instead. Revisit with #150 if the owner wants it.
- Client-certificate authentication of birdcage to the LAPI. Still
  declined for ADR-0014's reason, and now for one more: it would mean
  the LAPI trusting birdcage's CA for login *on purpose*.
- A sign-a-CSR mode. No `openssl` in the image; no security gain while
  birdcage holds the root key.
- Operator-chosen lifetime, key type, subject or extra extensions.
- A startup reminder read back from `audit_log`. The at-issuance and
  at-use reminders cover the gap until #150's reminder machinery
  exists, which is the right home for a scheduled one.
- Non-Docker deployments where the LAPI is on another machine. The
  command works (`--out` a directory, copy the three files, delete the
  local copies); the docs say that is the operator's shred problem,
  not birdcage's.

## Consequences

- `internal/ca` gains `IssueLAPI` (the profile above), `PublicCert`
  (read `ca.pem` without loading or creating a key) and an exported
  atomic file writer. `internal/crowdsec` gains name validation, the
  three-file writer, the trust-pool builder and the peer-expiry
  warning. `cmd/birdcage` gains `crowdsec cert`. No new table, module
  or variable.
- `BIRDCAGE_CROWDSEC_CA_FILE`'s meaning narrows from "the only anchor"
  to "an anchor besides birdcage's own CA"; `docs/configuration.md`'s
  table row and the "All of them, or none of them" paragraph say so.
- ADR-0014 decision 7's trust row gains the own-CA anchor; its
  `docs/configuration.md` section gains "Let birdcage issue the LAPI's
  certificate" with the Compose example, the OU warning, the renewal
  steps and the restart note.
- `SECURITY.md`'s CA paragraph lists the LAPI leaf among the
  certificates the CA issues, with the name-refusal rule.
- #150's design gets two inputs from here: the LAPI leaf is one more
  thing to reissue during overlap, and the trust-pool builder already
  accepts several roots.
- The e2e stack runs two LAPI containers on the `big` lane; the second
  exists only to present a certificate birdcage did not issue.

## Open question for the owner

**Q1. Birdcage writing the LAPI's private key to `--out` (decision
4).** #62's rule is "exactly one private key exists as a file on the
birdcage host: the CA's". Decision 4 reads that as a rule about
birdcage's own keys, and writes the LAPI's key once, to the LAPI's
storage, keeping nothing. Options:

- **a. As decided above (recommended).** `--out <dir>` writes
  `lapi-key.pem` `0600` atomically, refuses to overwrite without
  `--replace`, refuses the CA directory, keeps no copy. The operator's
  Compose example mounts the CrowdSec TLS volume for the one command,
  so the key never sits in birdcage's own volume.
- **b. Print the PEM to stdout, write nothing.** Birdcage's process
  never writes a key file; the operator redirects. The key then passes
  through a terminal and is created with the operator's umask (often
  `0644` for a moment), and the "one command" becomes a redirect plus
  two `chmod`s. Worse in practice, cleaner on paper.
- **c. Neither; the operator keeps making the certificate by hand**,
  which is today, and #163 closes as declined.

If **a** is confirmed, this ADR's status becomes Accepted with no
other change.
