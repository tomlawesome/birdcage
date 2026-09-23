// The decisions CanaryPage.svelte itself makes, as opposed to the
// lib/canary modules already covered by their own tests: which blocks
// render, what a card's outline says, and that the page draws a ledger
// it has nothing to put in without pretending otherwise.
import { render, screen } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import CanaryPage from './CanaryPage.svelte'
import { sceneInput, type SceneName } from './lib/canary/fixtures'

function mount(scene: SceneName, mutate: (input: ReturnType<typeof sceneInput>) => void = () => {}) {
  const input = sceneInput(scene)
  mutate(input)
  return render(CanaryPage, {
    page: input.page,
    trace: input.trace,
    visitors: input.visitors,
    history: input.history,
    range: '14d',
  })
}

describe('the four blocks', () => {
  it('draws the sentence, the line, the ledger, the thread and the facts', () => {
    const { container } = mount('quiet')
    expect(container.querySelector('.hero')?.textContent).toBe('canary-iot is quiet, and answers when tested.')
    expect(screen.getByRole('img', { name: /canary-iot: its heartbeat/ })).toBeTruthy()
    expect(container.querySelectorAll('.strip .svc')).toHaveLength(4)
    expect(container.querySelectorAll('.thread .ev')).toHaveLength(6)
    expect(container.querySelectorAll('.facts span')).toHaveLength(20)
  })

  it('shows only the actions the state earns', () => {
    const { container } = mount('silent')
    const pills = [...container.querySelectorAll('.acts .pill')].map((p) => p.textContent)
    expect(pills).toEqual(['lookback in mikroview ▸', 'mark as maintenance'])
  })
})

describe('a card\'s outline carries the verdict', () => {
  it('a service that did not answer takes the ink outline, not the alarm colour', () => {
    const { container } = mount('failed')
    const telnet = [...container.querySelectorAll('.strip .svc')].find((c) => c.textContent?.startsWith('telnet'))!
    expect(telnet.classList.contains('no')).toBe(true)
    expect(telnet.textContent).toContain('did not answer')
    expect(telnet.textContent).toContain('no proof')
  })

  it('untested is dashed, and never reads as a fault', () => {
    const { container } = mount('quiet', (input) => {
      input.page.canary.ports = `${input.page.canary.ports} · ntp 123`
    })
    const ntp = [...container.querySelectorAll('.strip .svc')].find((c) => c.textContent?.startsWith('ntp'))!
    expect(ntp.classList.contains('un')).toBe(true)
    expect(ntp.classList.contains('no')).toBe(false)
    expect(ntp.textContent).toContain('untested')
  })
})

describe('nothing to show is said in words, not left blank', () => {
  it('a canary with no completed run has no strip and says why', () => {
    const { container } = mount('quiet', (input) => {
      input.page.canary.self_test = []
      input.page.self_test_runs = []
    })
    expect(container.querySelector('.strip')).toBeNull()
    expect(container.querySelector('.none')?.textContent).toContain('No self-test has completed')
  })
})

describe('the thread\'s dots', () => {
  it('a state still true is hollow; a cleared one is filled', () => {
    const { container } = mount('silent')
    const rows = [...container.querySelectorAll('.thread .ev')]
    expect(rows[0].classList.contains('live')).toBe(true)
    expect(rows[1].classList.contains('ok')).toBe(true)
    expect(rows[2].classList.contains('fault')).toBe(true)
  })
})
