// A sentence is built as a list of segments rather than one HTML string,
// so tests can assert on the plain text (join all `text`) and on which
// fragment carries which styling, and so components can render it with
// Svelte's own escaping instead of {@html} -- every segment may embed
// attacker-supplied data (a visitor's source IP, a canary's name), and
// none of that should ever be interpreted as markup.
export interface Segment {
  text: string
  /** Rendered as <b>. */
  bold?: boolean
  /** Rendered as <span class={cls}> (or <b class={cls}> when bold too) -- matches gen.py's .ok/.r/.ip/.mute classes. */
  cls?: string
}

export function plainText(segments: Segment[]): string {
  return segments.map((s) => s.text).join('')
}
