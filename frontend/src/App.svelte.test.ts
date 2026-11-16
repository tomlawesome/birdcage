import { render, screen } from '@testing-library/svelte'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.svelte'

const signedIn = { setupRequired: false, ssoAvailable: false, authenticated: true, hasLocalPassword: true, ssoConnected: false, mustChangePassword: false, mustEnrolSecondFactor: false, mustEnrolPasskey: false, hasTOTP: true, username: 'tom', role: 'admin' }

describe('the chrome (#36)', () => {
  beforeEach(() => {
    // No backend in this test -- the component's own try/catch leaves
    // the status slot in its neutral state, which is all this test
    // needs; what matters here is the chrome markup, not fetched data.
    // Signed in (issue #8): the session is read before the chrome shows;
    // every dashboard read still fails.
    vi.stubGlobal(
      'fetch',
      vi.fn((path: string) =>
        path === '/api/auth/session'
          ? Promise.resolve({ ok: true, status: 200, json: async () => signedIn })
          : Promise.reject(new Error('no backend in this test')),
      ),
    )
  })

  it('shows the wordmark with CAGE in the accent', async () => {
    render(App)
    const wordmark = await screen.findByLabelText('Birdcage')
    expect(wordmark.textContent).toBe('BIRDCAGE')
    expect(wordmark.querySelector('em')?.textContent).toBe('CAGE')
  })

  it('renders all five range chips', async () => {
    render(App)
    const group = await screen.findByRole('group', { name: 'Time range' })
    const labels = ['15 m', '1 h', '24 h', '14 d', '90 d']
    for (const label of labels) {
      expect(screen.getByRole('button', { name: label })).toBeTruthy()
    }
    expect(group.querySelectorAll('button')).toHaveLength(labels.length)
    // 14 d is the default active range.
    expect(screen.getByRole('button', { name: '14 d' }).getAttribute('aria-pressed')).toBe('true')
  })

  it('renders the sideways deck with its four views', async () => {
    render(App)
    const deck = await screen.findByRole('navigation', { name: 'Views' })
    const items = ['THE TRACE', 'VISITORS', 'AUDIT LOG', 'SETTINGS']
    for (const item of items) {
      expect(screen.getByRole('button', { name: item })).toBeTruthy()
    }
    expect(deck.querySelectorAll('button')).toHaveLength(items.length)
    expect(screen.getByRole('button', { name: 'THE TRACE' }).getAttribute('aria-current')).toBe('true')
  })

  it('renders the three tabs and the info button', async () => {
    render(App)
    expect(await screen.findByRole('navigation', { name: 'Sections' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'the cage' }).getAttribute('aria-current')).toBe('true')
    expect(screen.getByRole('button', { name: 'visitors' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'audit log' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'About birdcage' })).toBeTruthy()
  })
})
