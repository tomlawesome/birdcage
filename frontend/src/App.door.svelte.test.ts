import { fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.svelte'
import quiet from './dev/fixtures/quiet.json'
import { onSignedOut } from './lib/api'
import { accountReply, deferred, flush, jsonReply, session, stubBrowser, stubServer } from './door/testkit'

class FakeEventSource {
  onmessage: unknown = null
  constructor(public url: string) {}
  close() {}
}

const signedIn = (over: Record<string, unknown> = {}) => session({ authenticated: true, username: 'ana', role: 'admin', ...over })

function dashboard(extra: Record<string, never> = {}) {
  return {
    'GET /api/canaries': jsonReply(quiet.canaries),
    'GET /api/visitors': jsonReply(quiet.visitors),
    'GET /api/trace': jsonReply(quiet.trace),
    'GET /api/history': jsonReply({ range: '14d', since: quiet.trace.now, until: quiet.trace.now, periods: [], summary: [] }),
    'GET /api/mail': jsonReply({ configured: false, last_sent_at: null, failing_since: null, last_error: null, pending: 0, suppressed: 0 }),
    ...extra,
  }
}
const isDashboard = (path: string) => !path.startsWith('/api/auth/')

beforeEach(() => {
  stubBrowser()
  vi.stubGlobal('EventSource', FakeEventSource)
  location.hash = ''
})
afterEach(() => {
  vi.unstubAllGlobals()
  onSignedOut(() => {})
})

describe('App and the door', () => {
  it('reads the session before any dashboard request', async () => {
    const gate = deferred<Response>()
    const server = stubServer({ 'GET /api/auth/session': () => gate.promise, ...dashboard() })
    render(App)
    await flush()
    await flush()
    expect(server.calls.map((c) => c.path)).toEqual(['/api/auth/session'])
    gate.resolve(jsonReply(signedIn()))
    await waitFor(() => expect(server.calls.some((c) => isDashboard(c.path))).toBe(true))
    expect(server.calls[0].path).toBe('/api/auth/session')
  })

  it('shows the door, and requests no dashboard route, when not signed in', async () => {
    const server = stubServer({ 'GET /api/auth/session': jsonReply(session()), ...dashboard() })
    render(App)
    expect(await screen.findByPlaceholderText('account')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Enter' })).toBeTruthy()
    await flush()
    expect(server.calls.filter((c) => isDashboard(c.path))).toEqual([])
  })

  it('shows the door for first run, with no dashboard request', async () => {
    const server = stubServer({ 'GET /api/auth/session': jsonReply(session({ setupRequired: true })), ...dashboard() })
    render(App)
    expect(await screen.findByRole('heading', { name: 'Create the admin account' })).toBeTruthy()
    await flush()
    expect(server.calls.filter((c) => isDashboard(c.path))).toEqual([])
  })

  it('shows the door while a second step is owed, with no dashboard request', async () => {
    const server = stubServer({ 'GET /api/auth/session': jsonReply(signedIn({ mustEnrolSecondFactor: true })), ...dashboard() })
    render(App)
    expect(await screen.findByRole('heading', { name: 'Add a second step' })).toBeTruthy()
    await flush()
    expect(server.calls.filter((c) => isDashboard(c.path))).toEqual([])
  })

  it('shows the expired screen when the session is resumable', async () => {
    stubServer({ 'GET /api/auth/session': jsonReply(session({ resumable: true })), ...dashboard() })
    render(App)
    expect(await screen.findByRole('heading', { name: 'Session expired' })).toBeTruthy()
  })

  it('when signed in shows the dashboard and no door', async () => {
    const server = stubServer({ 'GET /api/auth/session': jsonReply(signedIn()), ...dashboard() })
    render(App)
    await waitFor(() => expect(server.calls.some((c) => c.path.startsWith('/api/canaries'))).toBe(true))
    expect(screen.queryByPlaceholderText('account')).toBeNull()
    expect(screen.queryByRole('heading', { name: 'Session expired' })).toBeNull()
    expect(screen.getByRole('navigation', { name: 'Sections' })).toBeTruthy()
  })

  it("the name chip shows the session's username and role", async () => {
    stubServer({ 'GET /api/auth/session': jsonReply(signedIn({ username: 'priya', role: 'viewer' })), ...dashboard() })
    render(App)
    expect(await screen.findByText('priya (viewer)')).toBeTruthy()
  })

  it('a different session shows a different chip (not fixed text)', async () => {
    stubServer({ 'GET /api/auth/session': jsonReply(signedIn({ username: 'omar', role: 'admin' })), ...dashboard() })
    render(App)
    expect(await screen.findByText('omar (admin)')).toBeTruthy()
    expect(screen.queryByText('priya (viewer)')).toBeNull()
  })

  it('a later 401 from a dashboard request shows the door (sign in when not resumable)', async () => {
    let n = 0
    const server = stubServer({
      'GET /api/auth/session': [jsonReply(signedIn()), jsonReply(session())],
      ...dashboard({ 'GET /api/trace': () => (n++ === 0 ? jsonReply(quiet.trace) : new Response('', { status: 401 })) } as never),
    })
    render(App)
    await waitFor(() => expect(server.calls.some((c) => c.path.startsWith('/api/trace'))).toBe(true))
    // force a refresh: the range chips refetch everything
    const chip = await screen.findByRole('button', { name: '24 h' })
    chip.click()
    expect(await screen.findByPlaceholderText('account')).toBeTruthy()
  })

  it('a later 401 shows the expired screen when the session says resumable, with the name the tab had', async () => {
    let n = 0
    const server = stubServer({
      'GET /api/auth/session': [jsonReply(signedIn({ username: 'ana' })), jsonReply(session({ resumable: true }))],
      ...dashboard({ 'GET /api/trace': () => (n++ === 0 ? jsonReply(quiet.trace) : new Response('', { status: 401 })) } as never),
    })
    render(App)
    await waitFor(() => expect(server.calls.some((c) => c.path.startsWith('/api/trace'))).toBe(true))
    ;(await screen.findByRole('button', { name: '24 h' })).click()
    expect(await screen.findByRole('heading', { name: 'Session expired' })).toBeTruthy()
    expect(screen.getByText('ana')).toBeTruthy()
  })
})

// W-S2 (#210): the door opening onto the dashboard fades for 750 ms. The
// shared browser stub reports reduced motion, so these turn it off.
const motion = () =>
  vi.stubGlobal(
    'matchMedia',
    vi.fn((q: string) => ({ matches: false, media: q, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, onchange: null, dispatchEvent: () => false })),
  )
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms))

async function signInThroughDoor() {
  await screen.findByPlaceholderText('account')
  await fireEvent.input(screen.getByPlaceholderText('account'), { target: { value: 'ana' } })
  await fireEvent.input(screen.getByPlaceholderText('password'), { target: { value: 'hunter2hunter2' } })
  await fireEvent.click(screen.getByRole('button', { name: 'Enter' }))
  return screen.findByRole('button', { name: 'ana (admin)' })
}

describe('the door opening onto the dashboard (W-S2)', () => {
  it('signing out while the opened door is still fading shows the sign-in form again', async () => {
    motion()
    stubServer({
      'GET /api/auth/session': [jsonReply(session()), jsonReply(signedIn()), jsonReply(session())],
      'POST /api/auth/login': accountReply(),
      'POST /api/auth/logout': jsonReply({}),
      ...dashboard(),
    })
    render(App)
    const chip = await signInThroughDoor()
    await fireEvent.click(chip)
    await fireEvent.click(await screen.findByRole('menuitem', { name: 'Sign out' }))
    await wait(800)
    expect(await screen.findByPlaceholderText('account')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Enter' })).toBeTruthy()
  })

  it('a 401 while the opened door is still fading shows the sign-in form again', async () => {
    motion()
    let n = 0
    stubServer({
      'GET /api/auth/session': [jsonReply(session()), jsonReply(signedIn()), jsonReply(session())],
      'POST /api/auth/login': accountReply(),
      ...dashboard({ 'GET /api/trace': () => (n++ === 0 ? jsonReply(quiet.trace) : new Response('', { status: 401 })) } as never),
    })
    render(App)
    await signInThroughDoor()
    await fireEvent.click(await screen.findByRole('button', { name: '24 h' }))
    await wait(800)
    expect(await screen.findByPlaceholderText('account')).toBeTruthy()
  })

  it('signing in keeps the same door fading, then removes it and keeps the chip', async () => {
    motion()
    stubServer({
      'GET /api/auth/session': [jsonReply(session()), jsonReply(signedIn())],
      'POST /api/auth/login': accountReply(),
      ...dashboard(),
    })
    render(App)
    await signInThroughDoor()
    expect(document.querySelectorAll('.door').length).toBe(1)
    expect(document.querySelector('.door')!.classList.contains('leaving')).toBe(true)
    await wait(800)
    expect(document.querySelector('.door')).toBeNull()
    expect(screen.getByRole('button', { name: 'ana (admin)' })).toBeTruthy()
  })
})

// GPF1-F1 (#210): gauntlet v0.4.2 (docs/api/auth.yaml, the Forbidden
// response) sends a gate 403 as a problem document whose type ends
// #must-change-password (or must-enrol-factor, must-enrol-passkey), with
// the same name in the X-Auth-Gate header.
function gate(kind: string): Response {
  return new Response(
    JSON.stringify({ type: `https://github.com/tomlawesome/gauntlet/blob/main/docs/api/errors.md#${kind}`, title: kind, status: 403, detail: 'detail text' }),
    { status: 403, headers: { 'Content-Type': 'application/problem+json', 'X-Auth-Gate': kind } },
  )
}

describe('a gate 403 from a dashboard read (GPF1-F1)', () => {
  it('must-change-password brings up the new-password door screen', async () => {
    let n = 0
    const server = stubServer({
      'GET /api/auth/session': [jsonReply(signedIn()), jsonReply(signedIn({ mustChangePassword: true }))],
      ...dashboard({ 'GET /api/trace': () => (n++ === 0 ? jsonReply(quiet.trace) : gate('must-change-password')) } as never),
    })
    render(App)
    await waitFor(() => expect(server.calls.some((c) => c.path.startsWith('/api/trace'))).toBe(true))
    ;(await screen.findByRole('button', { name: '24 h' })).click()
    expect(await screen.findByRole('heading', { name: 'Set a new password' })).toBeTruthy()
  })

  it('must-enrol-factor brings up the second-step door screen', async () => {
    let n = 0
    stubServer({
      'GET /api/auth/session': [jsonReply(signedIn()), jsonReply(signedIn({ mustEnrolSecondFactor: true }))],
      ...dashboard({ 'GET /api/trace': () => (n++ === 0 ? jsonReply(quiet.trace) : gate('must-enrol-factor')) } as never),
    })
    render(App)
    ;(await screen.findByRole('button', { name: '24 h' })).click()
    expect(await screen.findByRole('heading', { name: 'Add a second step' })).toBeTruthy()
  })

  it('a plain 403 does not re-read the session', async () => {
    let n = 0
    const server = stubServer({
      'GET /api/auth/session': [jsonReply(signedIn()), jsonReply(session())],
      ...dashboard({
        'GET /api/trace': () =>
          n++ === 0 ? jsonReply(quiet.trace) : new Response(JSON.stringify({ type: 'https://github.com/tomlawesome/gauntlet/blob/main/docs/api/errors.md#forbidden', title: 'forbidden', status: 403 }), { status: 403, headers: { 'Content-Type': 'application/problem+json' } }),
      } as never),
    })
    render(App)
    ;(await screen.findByRole('button', { name: '24 h' })).click()
    await wait(100)
    expect(server.to('GET', '/api/auth/session').length).toBe(1)
    expect(screen.queryByPlaceholderText('account')).toBeNull()
  })
})
