// Port of gen.py's beats(): heartbeat tick marks, one per minute, only
// inside the stretched 15-minute segment. gen.py synthesises the offsets
// itself (off, off+60, off+120, ...); the real component has actual
// heartbeat timestamps from the trace API, so this takes those and turns
// them into the same "ago" list, still restricted to the stretched window
// and still respecting `since` (a silent canary's marks stop at the last
// real heartbeat -- gen.py's SILENT_LAST).
export function beatAgos(beats: string[], now: Date, sinceAgo = 0): number[] {
  const nowMs = now.getTime()
  return beats
    .map((iso) => (nowMs - new Date(iso).getTime()) / 1000)
    .filter((ago) => ago >= 0 && ago < 900 && ago >= sinceAgo)
}
