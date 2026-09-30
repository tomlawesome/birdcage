/** Canary.ports is a display string, "ssh 22 · http 80 · smb 445"
 * (types.ts / gen.py's `ports` dict rendered). Parsed back to a
 * service -> port lookup for rows that name a specific service, e.g.
 * "198.51.100.7 knocks on canary-iot :445" (gen.py NIGHT_HITS repeat row). */
export function portForService(ports: string, service: string): string | null {
  for (const part of ports.split(' · ')) {
    const [name, port] = part.trim().split(/\s+/)
    if (name === service) return port ?? null
  }
  return null
}
