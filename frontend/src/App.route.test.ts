// Issue #118: the app's whole router, through the component. lib/route.ts
// covers the parsing; this covers what App.svelte does with it -- which
// page fills main, what the tabs say, and what a canary that does not
// exist looks like.
import { render, screen, waitFor } from '@testing-library/svelte'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App.svelte'
import fixture from './dev/fixtures/canary-quiet.json'

function stubFetch(canaryStatus = 200) {
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      const body = url.startsWith('/api/canaries')
        ? fixture.canaries
        : url.startsWith('/api/canary')
          ? fixture.canary['canary-iot']
          : url.startsWith('/api/visitors')
            ? fixture.visitors
            : url.startsWith('/api/trace')
              ? fixture.trace
              : url.startsWith('/api/history')
                ? fixture.history
                : fixture.mail
      const ok = url.startsWith('/api/canary?') ? canaryStatus === 200 : true
      return Promise.resolve({ ok, status: ok ? 200 : canaryStatus, json: () => Promise.resolve(body) })
    }),
  )
}

beforeEach(() => {
  // EventSource is issue #44's push channel; jsdom has none, and the
  // component already treats that as "poll only".
  vi.stubGlobal('EventSource', undefined)
})

afterEach(() => {
  location.hash = ''
  vi.unstubAllGlobals()
})

describe('the hash decides which page fills main', () => {
  it('no hash is the cage', async () => {
    stubFetch()
    render(App)
    await waitFor(() => expect(screen.getByRole('main', { name: 'the cage' })).toBeTruthy())
    expect(document.querySelector('.tabs .crumb')).toBeNull()
  })

  it('#/canaries/<id> is that canary\'s own page, with its crumb after the cage tab', async () => {
    location.hash = '#/canaries/canary-iot'
    stubFetch()
    const { container } = render(App)
    await waitFor(() => expect(container.querySelector('.strip .svc')).toBeTruthy())
    expect(container.querySelector('.tabs .crumb')?.textContent).toContain('canary-iot')
    expect(container.querySelector('.hero')?.textContent).toBe('canary-iot is quiet, and answers when tested.')
    // The cage's own blocks are gone, not merely hidden.
    expect(container.querySelector('.tiles')).toBeNull()
  })

  it('a canary that does not exist says so, and offers the way back', async () => {
    location.hash = '#/canaries/canary-nope'
    stubFetch(404)
    const { container } = render(App)
    await waitFor(() => expect(container.querySelector('.state-line')?.textContent).toContain('no agent called'))
    expect(container.querySelector('.state-line a')?.getAttribute('href')).toBe('#/')
  })

  it('follows a hashchange without a reload', async () => {
    stubFetch()
    const { container } = render(App)
    await waitFor(() => expect(container.querySelector('.tiles')).toBeTruthy())
    location.hash = '#/canaries/canary-iot'
    window.dispatchEvent(new HashChangeEvent('hashchange'))
    await waitFor(() => expect(container.querySelector('.strip .svc')).toBeTruthy())
  })
})
