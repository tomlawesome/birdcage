import { fireEvent, render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.svelte'
import quiet from './dev/fixtures/quiet.json'
import { onSignedOut } from './lib/api'
import { deferred, flush, jsonReply, session, stubBrowser, stubServer } from './door/testkit'

class FakeEventSource {
  onmessage: unknown = null
  constructor(public url: string) {}
  close() {}
}

const signedIn = () => session({ authenticated: true, username: 'wren', role: 'viewer' })

function dashboard() {
  return {
    'GET /api/canaries': jsonReply(quiet.canaries),
    'GET /api/visitors': jsonReply(quiet.visitors),
    'GET /api/trace': jsonReply(quiet.trace),
    'GET /api/history': jsonReply({ range: '14d', since: quiet.trace.now, until: quiet.trace.now, periods: [], summary: [] }),
    'GET /api/mail': jsonReply({ configured: false, last_sent_at: null, failing_since: null, last_error: null, pending: 0, suppressed: 0 }),
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

async function shell(logout: Response | Promise<Response> | (() => Response | Promise<Response>) = jsonReply({})) {
  const server = stubServer({
    'GET /api/auth/session': jsonReply(signedIn()),
    'POST /api/auth/logout': typeof logout === 'function' ? () => logout() : logout,
    ...dashboard(),
  })
  render(App)
  const chip = await screen.findByRole('button', { name: 'wren (viewer)' })
  return { server, chip }
}

async function open(chip: HTMLElement) {
  await fireEvent.click(chip)
  return screen.findByRole('menuitem', { name: 'Sign out' })
}

// jsdom never turns a key into a click, so a test that fires the click
// itself passes whatever the chip is. This does what a browser does: a
// native, enabled <button> is activated by Enter on keydown and by Space
// on keyup, unless a handler cancelled the key. Any other element only
// gets the key events and must handle them itself.
async function press(el: HTMLElement, key: 'Enter' | ' ') {
  const down = new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true })
  el.dispatchEvent(down)
  const native = el instanceof HTMLButtonElement && !el.disabled
  if (native && key === 'Enter' && !down.defaultPrevented) el.click()
  const up = new KeyboardEvent('keyup', { key, bubbles: true, cancelable: true })
  el.dispatchEvent(up)
  if (native && key === ' ' && !down.defaultPrevented && !up.defaultPrevented) el.click()
  await flush()
}

describe('sign-out menu', () => {
  it('the chip is a menu button, closed at first, with no menu in the page', async () => {
    const { chip } = await shell()
    expect(chip.getAttribute('aria-haspopup')).toBe('menu')
    expect(chip.getAttribute('aria-expanded')).toBe('false')
    expect(screen.queryByRole('menu')).toBeNull()
    expect(screen.queryByRole('menuitem')).toBeNull()
  })

  it('a click opens a menu with one item, Sign out, which has focus', async () => {
    const { chip } = await shell()
    const item = await open(chip)
    expect(screen.getAllByRole('menuitem')).toHaveLength(1)
    expect(document.activeElement).toBe(item)
    expect(chip.getAttribute('aria-expanded')).toBe('true')
  })

  it('Enter on the chip opens the menu', async () => {
    const { chip } = await shell()
    chip.focus()
    await press(chip, 'Enter')
    expect(await screen.findByRole('menuitem', { name: 'Sign out' })).toBeTruthy()
    expect(chip.getAttribute('aria-expanded')).toBe('true')
  })

  it('Space on the chip opens the menu', async () => {
    const { chip } = await shell()
    chip.focus()
    await press(chip, ' ')
    expect(await screen.findByRole('menuitem', { name: 'Sign out' })).toBeTruthy()
    expect(chip.getAttribute('aria-expanded')).toBe('true')
  })

  it('Escape closes the menu and puts focus back on the chip', async () => {
    const { chip } = await shell()
    const item = await open(chip)
    await fireEvent.keyDown(item, { key: 'Escape' })
    await waitFor(() => expect(screen.queryByRole('menu')).toBeNull())
    expect(screen.queryByRole('menuitem')).toBeNull()
    expect(chip.getAttribute('aria-expanded')).toBe('false')
    expect(document.activeElement).toBe(chip)
  })

  it('a click outside closes the menu', async () => {
    const { chip } = await shell()
    await open(chip)
    await fireEvent.pointerDown(document.body)
    await fireEvent.mouseDown(document.body)
    await fireEvent.click(document.body)
    await waitFor(() => expect(screen.queryByRole('menuitem')).toBeNull())
    expect(chip.getAttribute('aria-expanded')).toBe('false')
  })

  it('choosing Sign out sends one POST /api/auth/logout with X-Requested-With: birdcage', async () => {
    const { server, chip } = await shell()
    await fireEvent.click(await open(chip))
    await waitFor(() => expect(server.to('POST', '/api/auth/logout')).toHaveLength(1))
    expect(server.to('POST', '/api/auth/logout')[0].headers['x-requested-with']).toBe('birdcage')
  })

  it('on success the sign-in screen shows and no dashboard request follows', async () => {
    const { server, chip } = await shell()
    await fireEvent.click(await open(chip))
    expect(await screen.findByPlaceholderText('account')).toBeTruthy()
    expect(screen.getByPlaceholderText('password')).toBeTruthy()
    const after = server.calls.length
    await flush()
    await flush()
    expect(server.calls.slice(after).filter((c) => isDashboard(c.path))).toEqual([])
    expect(server.to('POST', '/api/auth/logout')).toHaveLength(1)
  })

  it('when the request fails the menu stays open with an alert and the dashboard stays', async () => {
    const { chip } = await shell(new Response('', { status: 500 }))
    await fireEvent.click(await open(chip))
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('Could not sign out. Try again.')
    expect(screen.getByRole('menuitem', { name: 'Sign out' })).toBeTruthy()
    expect(chip.getAttribute('aria-expanded')).toBe('true')
    expect(screen.queryByPlaceholderText('account')).toBeNull()
    expect(screen.getByRole('navigation', { name: 'Sections' })).toBeTruthy()
  })

  it('two clicks while the first request is unresolved send one request', async () => {
    const gate = deferred<Response>()
    const { server, chip } = await shell(() => gate.promise)
    const item = await open(chip)
    await fireEvent.click(item)
    await fireEvent.click(item)
    await flush()
    expect(server.to('POST', '/api/auth/logout')).toHaveLength(1)
    gate.resolve(jsonReply({}))
    expect(await screen.findByPlaceholderText('account')).toBeTruthy()
    expect(server.to('POST', '/api/auth/logout')).toHaveLength(1)
  })
})
