// Behind the door after a 401: the last session's dashboard data is
// gone, and the name chip is not shown without a signed-in session.
import { render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.svelte'
import quiet from './dev/fixtures/quiet.json'
import { onSignedOut } from './lib/api'
import { jsonReply, session, stubBrowser, stubServer } from './door/testkit'

class FakeEventSource {
  onmessage: unknown = null
  constructor(public url: string) {}
  close() {}
}

beforeEach(() => {
  stubBrowser()
  vi.stubGlobal('EventSource', FakeEventSource)
  location.hash = ''
})
afterEach(() => {
  vi.unstubAllGlobals()
  onSignedOut(() => {})
})

const signedIn = () => session({ authenticated: true, username: 'ana', role: 'admin' })
const history = () => jsonReply({ range: '14d', since: quiet.trace.now, until: quiet.trace.now, periods: [], summary: [] })
const mail = () => jsonReply({ configured: false, last_sent_at: null, failing_since: null, last_error: null, pending: 0, suppressed: 0 })

describe('behind the expired door', () => {
  it('drops the dashboard data and shows no name chip', async () => {
    let n = 0
    stubServer({
      'GET /api/auth/session': [jsonReply(signedIn()), jsonReply(session({ resumable: true }))],
      'GET /api/canaries': () => jsonReply(quiet.canaries),
      'GET /api/visitors': () => jsonReply(quiet.visitors),
      'GET /api/trace': () => (n++ === 0 ? jsonReply(quiet.trace) : new Response('', { status: 401 })),
      'GET /api/history': () => history(),
      'GET /api/mail': () => mail(),
    })
    render(App)
    await waitFor(() => expect(document.querySelector('.hero')).not.toBeNull())
    expect(screen.getByRole('button', { name: 'ana (admin)' })).toBeTruthy()
    ;(await screen.findByRole('button', { name: '24 h' })).click()
    expect(await screen.findByRole('heading', { name: 'Session expired' })).toBeTruthy()
    expect(document.querySelector('.hero')).toBeNull()
    expect(screen.queryByRole('button', { name: /^ana \(/ })).toBeNull()
    expect(screen.queryByText(/\(\)/)).toBeNull()
    expect(document.querySelector('.tile')).toBeNull()
  })
})
