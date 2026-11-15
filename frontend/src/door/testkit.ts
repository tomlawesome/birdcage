// Shared helpers for the door tests: a SessionState fixture, a fetch
// stub that records what was sent, and problem-document replies.
import { vi } from 'vitest'
import type { SessionState } from '../lib/auth'

export function session(over: Record<string, unknown> = {}): SessionState {
  return {
    setupRequired: false,
    authenticated: false,
    mustChangePassword: false,
    mustEnrolSecondFactor: false,
    mustEnrolPasskey: false,
    resumable: false,
    ssoAvailable: false,
    passkeys: { status: 'ready', signIn: false },
    ...over,
  } as unknown as SessionState
}

const PROBLEM_BASE = 'https://github.com/tomlawesome/gauntlet/blob/main/docs/api/errors.md#'

export function jsonReply(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

export function problem(kind: string, status: number, detail = 'detail text'): Response {
  return new Response(
    JSON.stringify({ type: PROBLEM_BASE + kind, title: kind, status, detail }),
    { status, headers: { 'Content-Type': 'application/problem+json' } },
  )
}

// Reply bodies. The specification does not give the wire shape of these;
// the fields are a superset so the build may pick any one reasonable name.
export function accountReply(username = 'ana', role = 'admin') {
  return jsonReply({ status: 'account', account: { username, role }, username, role })
}
export function secondFactorReply(methods: string[]) {
  return jsonReply({ status: 'secondFactor', challenge: 'secondFactor', secondFactor: methods, methods })
}
export function proveReply() {
  // gauntlet v0.4.2's ProveChallenge: {prove: 'passkey', passkeyOrigin}.
  return jsonReply({ status: 'prove', challenge: 'prove', prove: 'passkey', passkeyOrigin: 'http://localhost' })
}

export interface Call {
  method: string
  path: string
  headers: Record<string, string>
  body: unknown
  rawBody: string | undefined
}
type Reply = Response | Promise<Response>
type Handler = Reply | Reply[] | ((c: Call) => Reply)

/** Stubs global fetch. Keys are "METHOD /path". An array is answered in
 * order, the last entry repeating. Unlisted requests fail the test loudly. */
export function stubServer(routes: Record<string, Handler>) {
  const calls: Call[] = []
  const queues = new Map<string, Reply[]>()
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.pathname + input.search : input.url
    const method = (init?.method ?? 'GET').toUpperCase()
    const headers: Record<string, string> = {}
    new Headers(init?.headers).forEach((v, k) => (headers[k.toLowerCase()] = v))
    const rawBody = typeof init?.body === 'string' ? init.body : undefined
    let body: unknown = undefined
    if (rawBody !== undefined) {
      try {
        body = JSON.parse(rawBody)
      } catch {
        body = rawBody
      }
    }
    const call: Call = { method, path: url, headers, body, rawBody }
    calls.push(call)
    const key = `${method} ${url.split('?')[0]}`
    const h = routes[key]
    if (h === undefined) throw new Error(`unexpected request: ${key}`)
    if (typeof h === 'function') return h(call)
    if (Array.isArray(h)) {
      let q = queues.get(key)
      if (!q) {
        q = [...h]
        queues.set(key, q)
      }
      return q.length > 1 ? q.shift()! : q[0]
    }
    return h
  })
  vi.stubGlobal('fetch', fn)
  return {
    calls,
    fn,
    to: (method: string, path: string) => calls.filter((c) => c.method === method && c.path.split('?')[0] === path),
    keys: () => calls.map((c) => `${c.method} ${c.path.split('?')[0]}`),
  }
}

export function deferred<T>() {
  let resolve!: (v: T) => void
  const promise = new Promise<T>((r) => (resolve = r))
  return { promise, resolve }
}

/** jsdom has no matchMedia or canvas; the door's bars must cope, and the
 * tests only need the door's own behaviour. Reduced motion is on. */
export function stubBrowser() {
  vi.stubGlobal(
    'matchMedia',
    vi.fn((q: string) => ({
      matches: q.includes('reduce'),
      media: q,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      onchange: null,
      dispatchEvent: () => false,
    })),
  )
}

/** A navigator.credentials stand-in for the passkey flows. */
export function stubCredentials() {
  const buf = new Uint8Array([1, 2, 3]).buffer
  const credentials = {
    get: vi.fn(async () => ({ id: 'x', rawId: buf, type: 'public-key', response: { clientDataJSON: buf, authenticatorData: buf, signature: buf, userHandle: null }, getClientExtensionResults: () => ({}) })),
    create: vi.fn(async () => ({ id: 'x', rawId: buf, type: 'public-key', response: { clientDataJSON: buf, attestationObject: buf, getTransports: () => [] }, getClientExtensionResults: () => ({}) })),
  }
  Object.defineProperty(navigator, 'credentials', { value: credentials, configurable: true })
  return credentials
}

export const flush = () => new Promise((r) => setTimeout(r, 0))
