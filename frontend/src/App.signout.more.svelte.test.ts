// The sign-out menu, beyond the specification's own tests: it never
// comes back open with a stale alert after the door, Escape on the chip
// closes it, and a 401 from logout means already signed out.
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.svelte'
import quiet from './dev/fixtures/quiet.json'
import { onSignedOut } from './lib/api'
import { accountReply, jsonReply, problem, session, stubBrowser, stubServer } from './door/testkit'

const sources: FakeEventSource[] = []
class FakeEventSource {
  onmessage: (() => void) | null = null
  constructor(public url: string) {
    sources.push(this)
  }
  close() {}
}

beforeEach(() => {
  sources.length = 0
  stubBrowser()
  vi.stubGlobal('EventSource', FakeEventSource)
  location.hash = ''
})
afterEach(() => {
  vi.unstubAllGlobals()
  onSignedOut(() => {})
})

const signedIn = () => session({ authenticated: true, username: 'wren', role: 'viewer' })
const dashboard = (trace: () => Response = () => jsonReply(quiet.trace)) => ({
  'GET /api/canaries': () => jsonReply(quiet.canaries),
  'GET /api/visitors': () => jsonReply(quiet.visitors),
  'GET /api/trace': trace,
  'GET /api/history': () => jsonReply({ range: '14d', since: quiet.trace.now, until: quiet.trace.now, periods: [], summary: [] }),
  'GET /api/mail': () => jsonReply({ configured: false, last_sent_at: null, failing_since: null, last_error: null, pending: 0, suppressed: 0 }),
})

describe('sign-out menu, further', () => {
  it('after the door shows and the session resumes, the menu is closed with no alert', async () => {
    let n = 0
    stubServer({
      'GET /api/auth/session': [jsonReply(signedIn()), jsonReply(session({ resumable: true, username: 'wren' })), jsonReply(signedIn())],
      'POST /api/auth/logout': new Response('', { status: 500 }),
      'POST /api/auth/reauthenticate': accountReply('wren', 'viewer'),
      ...dashboard(() => (n++ === 1 ? new Response('', { status: 401 }) : jsonReply(quiet.trace))),
    })
    render(App)
    const chip = await screen.findByRole('button', { name: 'wren (viewer)' })
    await fireEvent.click(chip)
    await fireEvent.click(await screen.findByRole('menuitem', { name: 'Sign out' }))
    expect((await screen.findByRole('alert')).textContent).toContain('Could not sign out. Try again.')
    // A pushed event refetches; the trace answers 401 and the door shows.
    await waitFor(() => expect(sources.length).toBeGreaterThan(0))
    sources[sources.length - 1].onmessage?.()
    expect(await screen.findByRole('heading', { name: 'Session expired' })).toBeTruthy()
    await fireEvent.input(screen.getByPlaceholderText('password'), { target: { value: 'pw-fake-1' } })
    await fireEvent.click(screen.getByRole('button', { name: 'Continue' }))
    const again = await screen.findByRole('button', { name: 'wren (viewer)' })
    expect(again.getAttribute('aria-expanded')).toBe('false')
    expect(screen.queryByRole('menuitem')).toBeNull()
    expect(screen.queryByText('Could not sign out. Try again.')).toBeNull()
  })

  it('Escape on the chip closes the menu and keeps focus on the chip', async () => {
    stubServer({ 'GET /api/auth/session': jsonReply(signedIn()), ...dashboard() })
    render(App)
    const chip = await screen.findByRole('button', { name: 'wren (viewer)' })
    await fireEvent.click(chip)
    await screen.findByRole('menuitem', { name: 'Sign out' })
    chip.focus()
    await fireEvent.keyDown(chip, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('menuitem')).toBeNull())
    expect(chip.getAttribute('aria-expanded')).toBe('false')
    expect(document.activeElement).toBe(chip)
  })

  it('a 401 from logout shows the sign-in door, not the failure', async () => {
    const server = stubServer({
      'GET /api/auth/session': jsonReply(signedIn()),
      'POST /api/auth/logout': problem('sign-in-required', 401),
      ...dashboard(),
    })
    render(App)
    await fireEvent.click(await screen.findByRole('button', { name: 'wren (viewer)' }))
    await fireEvent.click(await screen.findByRole('menuitem', { name: 'Sign out' }))
    expect(await screen.findByPlaceholderText('account')).toBeTruthy()
    expect(screen.queryByText('Could not sign out. Try again.')).toBeNull()
    expect(server.to('POST', '/api/auth/logout')).toHaveLength(1)
  })
})
