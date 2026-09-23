// The app's whole router (issue #118). Two places exist -- the cage, and
// one canary's own page -- so this is a parser over location.hash, not a
// routing library: nothing here needs route parameters, guards, nested
// layouts or lazy segments, and a dependency that offers them would be
// more machinery than the app has routes.
//
// The hash, not the path: web/embed.go already falls back to index.html
// for an unknown path, but a hash needs no server agreement at all, so a
// bookmarked canary page resolves the same whether the build is served
// by birdcage, by `npm run dev`, or from a file. It also keeps the
// fixture-mode query string (?scene=) untouched, which is what the
// pixel gate drives the page with.

export type Route = { name: 'cage' } | { name: 'canary'; id: string }

const CANARY_PREFIX = '#/canaries/'

/** "#/canaries/canary-iot" -> the canary route; anything else is the
 * cage, including an empty hash and a malformed one -- an unknown
 * address lands on the fleet rather than on an error page. */
export function parseRoute(hash: string): Route {
  if (!hash.startsWith(CANARY_PREFIX)) return { name: 'cage' }
  const raw = hash.slice(CANARY_PREFIX.length)
  // Checked before decoding, not after: a canary id may legitimately
  // contain a slash, and canaryHref escapes it -- it is an *unescaped*
  // slash that means a deeper path this app has no page for.
  if (raw === '' || raw.includes('/')) return { name: 'cage' }
  return { name: 'canary', id: decodeURIComponent(raw) }
}

/** The href a tile's link carries. encodeURIComponent, because a canary
 * id is operator-chosen text: it must survive the round trip through
 * parseRoute, and it must not be able to smuggle a second path segment
 * or a query string into the address bar. */
export function canaryHref(id: string): string {
  return `${CANARY_PREFIX}${encodeURIComponent(id)}`
}

/** The cage's own address -- "#/", not "", so clicking it from a canary
 * page is a real navigation that fires hashchange. */
export const cageHref = '#/'
