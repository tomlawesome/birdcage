# Birdcage v1 scope

## Purpose

Birdcage centralizes alerts from multiple OpenCanary honeypot instances into
a single dashboard, and attempts automated mitigating action (via CrowdSec
and RouterOS) against confirmed threats, with every automated action logged
to an append-only audit trail. Birdcage runs as a sidecar to mikroview,
sharing its design language and sign-in model but not its code -- see
[ADR-0003](adr/0003-mikroview-sidecar.md).

Work is tracked as three epics, each grouping the individual issues that
belong to it:

- [Epic: V1 foundation -- ingestion + dashboard (#9)](https://github.com/tomlawesome/birdcage/issues/9) -- wave 1
- [Epic: V1 automated mitigation (#10)](https://github.com/tomlawesome/birdcage/issues/10) -- wave 2
- [Epic: Deferred / future hardening (#11)](https://github.com/tomlawesome/birdcage/issues/11) -- wave 3

## In v1 (waves 1-2)

- Receiving and normalizing OpenCanary syslog output from many instances
  into a single store ([#2](https://github.com/tomlawesome/birdcage/issues/2)).
- A dashboard showing alerts across all registered instances, filterable by
  instance/source IP/service/time ([#3](https://github.com/tomlawesome/birdcage/issues/3)).
- A defined, concrete meaning for "intelligent analysis" of that activity
  ([#6](https://github.com/tomlawesome/birdcage/issues/6)) -- not shipped as
  an undefined aspiration.
- CrowdSec integration ([#4](https://github.com/tomlawesome/birdcage/issues/4))
  and RouterOS automated mitigation
  ([#5](https://github.com/tomlawesome/birdcage/issues/5)), both writing
  every action taken to the audit log.
- Authentication: local accounts plus self-hosted-only OIDC, modelled on
  mikroview's ([#8](https://github.com/tomlawesome/birdcage/issues/8)). The
  dashboard does not ship without it.

## Explicitly deferred (wave 3)

Tracked so these aren't lost, not because they're unimportant:

- Ansible-based rollout for new OpenCanary nodes ([#1](https://github.com/tomlawesome/birdcage/issues/1)).
- Postgres support, once multi-node/HA deployment is a real requirement ([#7](https://github.com/tomlawesome/birdcage/issues/7)).

## Explicitly out of scope for birdcage itself

- **Being the OpenCanary honeypot software.** Birdcage consumes OpenCanary's
  output; it does not replace or embed OpenCanary.
- **General-purpose SIEM functionality.** Birdcage is scoped to OpenCanary
  honeypot data and the mitigation actions that follow from it, not a
  broad log-aggregation platform.
- **Being mikroview's live-traffic viewer.** `tomlawesome/mikroview`
  remains the "interrogation helper" for real firewall traffic. Birdcage's
  only planned coupling to it is consuming its bounded IP+time lookback
  query ([mikroview#29](https://github.com/tomlawesome/mikroview/issues/29))
  if useful for correlation -- birdcage does not absorb mikroview's
  detectors or vice versa. How the two apps sit together -- same compose
  stack, API keys only -- is [ADR-0003](adr/0003-mikroview-sidecar.md).

## Decisions this scope depends on

See [ADR-0001](adr/0001-stack-and-storage.md) (stack, storage, v1 auth
stance), [ADR-0002](adr/0002-gitflow-branching.md) (branching model), and
[ADR-0003](adr/0003-mikroview-sidecar.md) (sidecar, auth model, Svelte).
