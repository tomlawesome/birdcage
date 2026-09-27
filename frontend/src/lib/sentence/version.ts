// Issue #54: birdcage stamps its own build the same way the agent
// already stamps itself -- MAJOR.MINOR.PATCH+commit, e.g. "0.1.1+edc3691a"
// (scripts/release-version.sh). Every line that names a version for an
// operator drops the commit suffix -- "runs 0.1.0, current 0.1.1", never
// the hash, which answers nothing an operator pasting an upgrade command
// needs.

/** "0.1.0+2ea21b94" -> "0.1.0"; "dev" (no '+') is returned unchanged. */
export function shortVersion(v: string): string {
  const i = v.indexOf('+')
  return i === -1 ? v : v.slice(0, i)
}

/** Whether the agent's own build trails birdcage's stamped version, by
 * MAJOR.MINOR.PATCH alone. A 'dev' agent is never behind -- it isn't a
 * release, so there is nothing to compare it against -- and neither is
 * a canary an older backend never sent `birdcage_version` for. */
export function isBehind(agentVersion: string | undefined, birdcageVersion: string | undefined): boolean {
  if (!agentVersion || !birdcageVersion || agentVersion === 'dev') return false
  return shortVersion(agentVersion) !== shortVersion(birdcageVersion)
}
