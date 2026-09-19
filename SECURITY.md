# Security policy

Birdcage is in early implementation (the HTTPS ingest submux -- per-canary
bearer tokens, TLS 1.3 -- and the command endpoint have landed; the agent
(#48) and enrolment (#47) have not; see [docs/v1-scope.md](docs/v1-scope.md))
-- this document describes the threat model and hardening it is designed
against, so that model is fixed before code lands rather than retrofitted
around whatever got built first. Update it as implementation reveals
details this can't predict yet.

## Threat model

Birdcage is meaningfully higher-stakes than a read-only tool: it will hold
live service-account credentials (CrowdSec, RouterOS) and, per
[ADR-0001](docs/adr/0001-stack-and-storage.md), is intended to take
automated mitigating action against real infrastructure. Compromise of
birdcage itself is not just an information leak -- it's a path to acting on
your network and firewall.

**A canary that cannot report is a security event, not an availability
one** (issue #45). A honeypot's entire value is a hit landing on the
dashboard; a canary that goes throttled, stops delivering, can't complete
its token rotation, or has a revoked token reused against it, is
indistinguishable from a quiet network unless birdcage says so loudly and
explicitly. Treating that as a mere uptime blip — logged, not surfaced —
lets an attacker who can overwhelm, starve or clone a canary's identity
buy the same silence a stopped agent would, with no operator ever told.
The dashboard surfaces each of these states on the canary's tile and in
the top-level status, ranked against — not below — an active attack.

**Authentication is part of v1** (changed 2026-09-12,
[ADR-0003](docs/adr/0003-mikroview-sidecar.md)): local accounts and
self-hosted-only OIDC, following
[mikroview](https://github.com/tomlawesome/mikroview)'s model. Until
[#8](https://gitlab.tomlawson.io/ai/birdcage/-/issues/8) lands, nothing gates
the dashboard, so the network-exposure guidance below is the only control.
This section is rewritten route-by-route when #8 lands.

## Data handling

- **Service-account credentials (CrowdSec, RouterOS) are secrets.** They
  must be supplied via environment variables or Docker/Compose secrets,
  never committed to a config file in the repo, and never logged --
  including in error messages or debug output. Treat a log line containing
  a bearer token or API key as a real leak, not a hypothetical one.
- **Alert and audit data is persisted**, unlike mikroview's in-memory-only
  model -- birdcage's whole purpose is centralized history across
  instances. SQLite and Postgres, both mandatory in v1, selected by
  `DATABASE_URL` (see [ADR-0001](docs/adr/0001-stack-and-storage.md) and
  [docs/configuration.md](docs/configuration.md)). Alert data (source IPs,
  timestamps, targeted services) is not highly sensitive on its own, but a
  SQLite database file should still be kept off any shared/multi-tenant
  filesystem, same guidance as mikroview's `config.yaml`, and a Postgres
  `DATABASE_URL` is itself a credential -- it carries a plaintext password --
  and must be handled with the same care as the CrowdSec/RouterOS secrets
  above (env var or secret, never committed, never logged).
- **The audit log is append-only by convention.** No application code path
  may issue `UPDATE`/`DELETE` against it. This is what makes "birdcage took
  automated action" reviewable and reversible rather than a black box --
  see [ADR-0001](docs/adr/0001-stack-and-storage.md).
- **Canary state history (`canary_state_periods`, issue #56) is written
  only by birdcage's own recorder** (`internal/history`), never from a
  request path, and only from signals that have already been
  authenticated and derived into a health state (`internal/store/health.go`)
  -- an operator or an enrolled canary cannot write a row directly, only
  cause one indirectly by behaving in a way birdcage already classifies.
  A 10-minute collapse window folds a rapidly re-entered state into its
  existing row instead of a new one, bounding how many rows an attacker
  who can pace a signal (crossing the ingest rate limit repeatedly, say)
  can make birdcage write. A gap in which birdcage itself was not
  running is recorded as its own "unobserved" span rather than left to
  read as a healthy period the dashboard never actually watched.
- **The SMTP account birdcage sends from (issue #55) is a secret**, and
  is handled exactly like the CrowdSec/RouterOS credentials above:
  supplied by file (`BIRDCAGE_MAIL_PASSWORD_FILE`, preferred — see
  [docs/configuration.md](docs/configuration.md#outbound-mail)) or
  environment variable, never committed, and never logged. It is never
  written to the `mail_outbox` table either: a rejected credential can
  come back out of an SMTP server's own error text, so every stored
  error and every log line is scrubbed of the username and password
  first, and the outbox is read back by `GET /api/mail` and shown on the
  dashboard. The connection carrying it is TLS from the first byte
  (port 465) or STARTTLS the operator asked for by name (587), always
  with the server's certificate verified; a server that does not offer
  the upgrade gets nothing rather than a cleartext login, and there is
  no plaintext mode and no skip-verify option anywhere in the
  configuration.
- **The mailbox is outside birdcage's trust boundary**, so a message
  carries a pointer and not a copy. It has a fixed subject naming no
  canary, and a body with no link, no token, no source address and no
  event content — only that a canary presented a revoked credential,
  which one, when, and "open birdcage the way you always do". Anyone who
  can read the operator's mail, or the mail server's logs, or a phone's
  lock screen over their shoulder, therefore learns nothing they could
  act on. The no-link rule is its own control: an alert mail that
  contains a link trains the operator to click links in alert mails,
  which is the delivery mechanism of the phishing message that would
  impersonate this one.
- **The mail rate limits are security controls, not tuning.** A token
  conflict is driven by a signal an attacker paces — they choose when
  the stolen credential is presented — so without a bound they would
  choose how much mail birdcage sends, which is an attack on the
  operator's mailbox, on their provider's standing, and on the operator's
  own attention. One message per canary per hour, twenty per hour across
  the fleet, both named constants in `internal/mail`. The same argument
  the 10-minute collapse window makes about row count above. Nothing a
  limit stops is discarded: a suppressed alert is counted against the
  most recent message for that canary, and the next one that goes out
  reports how many were suppressed and since when — a rate limit that
  silently drops what it stops is indistinguishable from a bug.
- **birdcage cannot send mail about its own death.** A process that is
  not running sends nothing, including a message saying it is not
  running, and no amount of care inside this codebase changes that. An
  operator who needs to know birdcage has stopped must watch it from
  outside — their own uptime monitoring, a container restart policy with
  alerting, or a periodic check against the dashboard. This is stated
  rather than worked around deliberately: a self-monitoring heartbeat
  inside the same process would be a feature that appears to cover the
  gap and does not.
- **The approval mailbox credential reads one mailbox, and birdcage is
  only the courier.** `BIRDCAGE_APPROVAL_IMAP_*` (see
  [docs/configuration.md](docs/configuration.md#approval-mailbox)) gives
  birdcage read access to one IMAP folder over fully verified TLS, with
  no plaintext mode and no skip-verify switch; prefer the password file
  over the environment variable, as with outbound mail. What that
  credential can do if it leaks is read the administrator's approval
  replies — it cannot send mail, and it cannot approve anything. Whoever
  holds it still cannot authorise an upgrade, because the approval is
  the administrator's own DKIM signature and only their mail provider
  can make one. Birdcage stores the reply byte for byte and carries it;
  every agent runs the same check for itself
  (`internal/agent/approval`), against DNS, on those bytes: exactly one
  valid signature from the pinned address's own domain, no `l=` tag
  leaving part of the body unsigned, `From`/`Subject`/`Date`/
  `Message-ID` all inside what was signed, the subject carrying the
  request's reference, the date inside its window, and the Message-ID
  never accepted before. So a birdcage that has been taken over can
  withhold an approval or invent one; it cannot make an invented one
  verify. `birdcage approval check <file.eml>` runs those same rules by
  hand, which is how an operator confirms their provider's signing works
  before they depend on it.

## Output escaping

Text birdcage did not generate itself -- a canary id, a service name, a
source address, an OpenCanary `raw` field -- comes from a machine we
expect to be attacked, and the stored record of it is evidence: nothing
upstream of output strips, rewrites, or otherwise sanitises it (the same
rule the Mockingbird agent follows for what it forwards). Escaping happens
only at the point that text is displayed, per surface:

- **Dashboard:** every value is rendered through Svelte's own text
  interpolation, never `{@html}`, so HTML/script injection is escaped
  the same way regardless of which field carries attacker-supplied text.
- **CLI (`birdcage canary mint | list | revoke`, and any future
  subcommand):** printed through `internal/term.Escape`, which renders
  C0, DEL, and C1 control characters as literal, visible text (e.g. an
  embedded escape sequence prints as `\x1b`, not as the raw byte) before
  it reaches a terminal, leaving ordinary printable text -- including
  non-ASCII -- untouched. It also escapes the bidirectional formatting
  characters, which reorder how surrounding text *displays* rather than
  moving the cursor: unescaped, they let a canary id read on screen as a
  different id than the one stored (the Trojan Source class,
  CVE-2021-42574). Without this, a crafted canary id or service
  name could hide output lines, overwrite what's already on screen, or
  make a revoked token's status print as active.

## Network exposure

- **Canary ingest — HTTPS**, address and on/off switch via
  `BIRDCAGE_INGEST_ADDR` (unset disables the listener entirely).
  **Bearer-token authenticated, TLS 1.3 minimum, HTTP/1.1 only.** A
  canary's agent (#48) posts batches of events to `POST /ingest/events`
  with `Authorization: Bearer <token>`; missing, unknown and revoked
  tokens all get an identical 401. This listener is on its own
  `*http.Server`, structurally unreachable from every dashboard route
  above and from the dashboard's own auth seam (issue #32). Its serving
  certificate is minted by birdcage's own CA (`BIRDCAGE_CA_DIR`, issue
  #47 slice 1) rather than an operator-supplied file; an unloadable or
  wrongly-permissioned CA directory stops birdcage at startup rather
  than falling back to plaintext. See
  [docs/configuration.md](docs/configuration.md#birdcage_ca_dir) for
  `BIRDCAGE_CA_DIR` and `BIRDCAGE_ADVERTISE_HOST`. Full threat model,
  rotation, and rate limits: issue #32.

  **Mutual TLS (issue #47 slice 3).** The bearer token alone is no longer
  enough: every connection must also present a client certificate issued
  by birdcage's own CA, and that certificate's subject must name the same
  canary the bearer token resolved to. A missing certificate is refused
  at the TLS handshake, before any request is read; a certificate for the
  wrong canary passes the handshake but is refused with the same 401 and
  an `ingest.client_cert_mismatch` audit entry. The enrolment listener
  (below) does not require one -- a canary has no certificate to present
  until `POST /enrol/provision` issues its first one.
- **Canary enrolment — HTTPS, default `:8444`** (`BIRDCAGE_ENROL_ADDR`;
  starts and stops with the ingest listener). Its own `*http.Server`,
  no client certificate, two routes: `POST /enrol/hello` accepts a
  deploy token minted by `birdcage canary enrol`, and
  `POST /enrol/provision` accepts the enrolment secret that call
  returned. Both credentials are stored only as SHA-256 hashes. A deploy
  token dies at first contact or five minutes after minting, whichever
  comes first; the secret is erased from birdcage at provisioning. Every
  refusal -- unknown, expired, already used -- is the same 401 body, and
  a replayed deploy token is also logged at WARN and audited as
  `enrolment.deploy_token_reuse`, because a second use is the signature
  of a copied command, not a retry. See [docs/enrolment.md](docs/enrolment.md).

  **What enrolment leaves behind (issue #61).** The canary side runs no
  script and no `curl`: the agent does the whole exchange in memory and
  writes only its own state directory (mode 0600, uid 65532). The
  enrolment secret, canary token and client key never appear in a
  command line, an environment variable, a log line or a temp file, and
  the OpenCanary child gets a filtered environment that carries none of
  the agent's inputs. The one accepted exception is the pasted `docker
  run` line itself: the deploy token sits in the operator's shell
  history and in `docker inspect` of that container for as long as
  either exists. What bounds it is that the token is spent at first
  contact and expired within five minutes regardless -- a copy yields a
  dead credential and a loud audit entry -- so clear the history line if
  you like, but nothing live is recoverable from it.
  **The one capability the canary holds (issue #65).** The agent watches
  for port scans itself, from inside the Mockingbird container, because
  OpenCanary's own port-scan module reads iptables log lines and so needs
  firewall rules and a root process -- neither of which that image has or
  should gain. It opens one `AF_PACKET` socket and attaches a kernel
  packet filter to it before the socket receives anything, so the kernel
  discards everything except bare TCP SYNs and UDP datagrams: the box is
  built to attract floods, and that filter is what stops a flood costing
  a syscall per packet. The privilege for this is `cap_net_raw` and
  nothing else, carried as a file capability on the binary so the process
  still runs as uid 65532 with no shell and no route to root; the
  container is run with `--cap-drop ALL --cap-add NET_RAW`. `CAP_NET_RAW`
  permits opening raw and packet sockets and nothing further, and the
  agent only ever reads -- it never sends on that socket. What it can see
  is every frame arriving on the container's own interfaces; what it
  cannot see is any other container, the host, or anything off that
  network segment, and it does not read IPv6, fragmented packets, or
  packet payloads at all -- only the addresses, ports and TCP flags it
  needs to tell a connection attempt from a reply. Omitting the
  capability is supported and safe: detection is off, the agent logs one
  line saying so, and every hit on an emulated service is still reported.
  Note that `--security-opt no-new-privileges` makes the kernel ignore
  file capabilities, so it and port-scan detection are mutually
  exclusive; see [docs/enrolment.md](docs/enrolment.md) for the trade.
- **Dashboard HTTPS — never plain HTTP across a network** (issue #63,
  owner decision: "we must never allow the GUI to run without https in
  some form"). `BIRDCAGE_HTTP_ADDR` (default `:8080`) together with
  `BIRDCAGE_HTTP_TLS_CERT` / `BIRDCAGE_HTTP_TLS_KEY` picks exactly one of
  three modes, decided once at startup by `internal/tlsconfig.Select`:
  (1) **operator-supplied certificate** -- both TLS variables set to PEM
  file paths, serves HTTPS on `BIRDCAGE_HTTP_ADDR` with the same TLS 1.3
  floor and HTTP/1.1-only posture as the canary ingest listener above,
  and reloads the pair whenever either file's mtime changes so a
  renewal needs no restart; (2) **plain HTTP bound strictly to
  loopback** -- no certificate configured and `BIRDCAGE_HTTP_ADDR`'s host
  is `127.0.0.1`, `::1` or `localhost`, or a unix socket
  (`unix:///path/to.sock`), for a reverse proxy in the same network
  namespace or sharing a volume; (3) **ACME** -- not implemented yet (a
  dependency decision the owner has not made). Anything else -- no
  certificate and a non-loopback or empty host, including the documented
  default `:8080` -- refuses to start with one message naming all three
  modes; it never raises a plaintext listener reachable off loopback.
  See [docs/configuration.md](docs/configuration.md#dashboard-tls).

  No authentication yet -- [issue #8](https://gitlab.tomlawson.io/ai/birdcage/-/issues/8)
  (ADR-0003) -- so whichever mode above is in use, treat it as reachable
  by anyone who can reach the listener. Every route below has the same
  gap:

  | Route            | Method | Auth                          |
  | ---------------- | ------ | ------------------------------ |
  | `/`              | GET    | requireAuth seam, pending #8  |
  | `/api/alerts`    | GET    | requireAuth seam, pending #8  |
  | `/api/instances` | GET    | requireAuth seam, pending #8  |
  | `/api/stats`     | GET    | requireAuth seam, pending #8  |
  | `/api/canaries`  | GET    | requireAuth seam, pending #8  |
  | `/api/visitors`  | GET    | requireAuth seam, pending #8  |
  | `/api/trace`     | GET    | requireAuth seam, pending #8  |
  | `/api/heartbeat` | POST   | requireAuth seam, pending #8  |
  | `/api/stream`    | GET    | requireAuth seam, pending #8  |

  `/api/stream` (issue #44) is a server-sent-events connection birdcage
  holds open rather than answering once, so until #8 lands it also caps
  total concurrent connections (`internal/stream.Hub`, 256) and drops the
  slowest subscriber's buffer rather than growing it without limit --
  mitigating the connection-exhaustion risk a held-open, unauthenticated
  route adds beyond the other routes above (see issue #44's Research
  section for the threat model and CVE search this came from). A dropped
  or refused stream falls back to the dashboard's existing 30s poll,
  which every route above already relies on.

## Recommended deployment hardening

- Terminate the dashboard with a real certificate
  (`BIRDCAGE_HTTP_TLS_CERT`/`BIRDCAGE_HTTP_TLS_KEY`) whenever it is
  reached across a network, or keep it strictly loopback-bound and put a
  TLS-terminating reverse proxy in front (issue #63) -- birdcage refuses
  to start rather than leave this to the operator to remember.
- Put it behind a VPN (e.g. WireGuard/Tailscale) if you need to reach it
  from outside that LAN -- there is no login screen to stop anyone who
  reaches it in v1.
- Keep CrowdSec/RouterOS credentials in environment variables or secrets,
  not in a config file that might be more widely readable than your
  environment.
- Restrict the RouterOS service account's own permissions to the minimum
  needed for the mitigation actions birdcage actually takes (e.g.
  firewall/address-list write access), not a full admin account -- birdcage
  compromising that account should not mean compromising the router.

## Reporting a vulnerability

This is a small, personally-maintained project without a formal disclosure
program. If you find a security issue, please open a GitHub issue
describing it -- for anything you'd rather not post publicly first, open a
minimal issue asking for a private contact channel instead of including
details in it.
