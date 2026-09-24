// The decisions CanaryPage.svelte itself makes, as opposed to the
// lib/canary modules already covered by their own tests: which blocks
// render, what a card's outline says, and that the page draws a ledger
// it has nothing to put in without pretending otherwise.
import { render, screen } from '@testing-library/svelte'
import { describe, expect, it } from 'vitest'
import CanaryPage from './CanaryPage.svelte'
import { sceneInput, type SceneName } from './lib/canary/fixtures'
import type { RunsResponse } from './lib/types'

function mount(
  scene: SceneName,
  mutate: (input: ReturnType<typeof sceneInput>) => void = () => {},
  runs: RunsResponse | null = null,
) {
  const input = sceneInput(scene)
  mutate(input)
  return render(CanaryPage, {
    page: input.page,
    trace: input.trace,
    visitors: input.visitors,
    history: input.history,
    runs,
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

// ADR-0012 (issue #116): a scanner's own proof -- the open run's stage
// timeline and the Runs list, shown only on a scanner's own page.
describe('ADR-0012: a scanner\'s stage timeline and Runs list', () => {
  it('a honeypot page never draws the scan section, even with a runs prop', () => {
    const { container } = mount('quiet', () => {}, { runs: [] })
    expect(container.querySelector('.scan-col')).toBeNull()
  })

  it('a scanner with an open run: the timeline marks the current stage', () => {
    const { container } = mount(
      'quiet',
      (input) => {
        input.page.facts.kind = 'scanner'
        input.page.canary.status = 'pending'
        input.page.canary.run = {
          trigger: 'proof',
          stage: 'mounts_checked',
          stage_at: input.trace.now,
          issued_at: input.trace.now,
        }
      },
      { runs: [] },
    )
    const steps = [...container.querySelectorAll('.scan-col .stage')]
    expect(steps).toHaveLength(6)
    expect(steps.map((s) => ['done', 'current', 'pending'].find((c) => s.classList.contains(c)))).toEqual([
      'done',
      'done',
      'current',
      'pending',
      'pending',
      'pending',
    ])
    expect(steps[2].textContent).toBe('mounts checked')
  })

  it('a scanner with no open run: says so instead of drawing an empty timeline', () => {
    const { container } = mount('quiet', (input) => {
      input.page.facts.kind = 'scanner'
    })
    expect(container.querySelector('.stages')).toBeNull()
    expect(container.querySelector('.scan-col .none')?.textContent).toContain('No scan is open')
  })

  it('a failing database refresh shows on the page, even under 24 hours', () => {
    const { container } = mount('quiet', (input) => {
      input.page.facts.kind = 'scanner'
      input.page.canary.db_refresh = { failing_since: '2026-09-05T21:00:00Z', last_error: 'timeout' }
    })
    expect(container.querySelector('.db-refresh')?.textContent).toContain('vulnerability list refresh failing since')
  })

  it('the Runs list draws trigger, issued, ended, verdict, last stage and reason -- never a run id', () => {
    const { container } = mount(
      'quiet',
      (input) => {
        input.page.facts.kind = 'scanner'
      },
      {
        runs: [
          {
            trigger: 'proof',
            issued_at: '2026-09-05T21:00:00Z',
            ended_at: '2026-09-05T21:02:00Z',
            verdict: 'fail',
            last_stage: 'scanning',
            reason: 'masked_paths incomplete',
            snapshot_id: 'snap-1',
          },
        ],
      },
    )
    const row = container.querySelector('.run-row')
    expect(row?.textContent).toContain('proof')
    expect(row?.textContent).toContain('fail')
    expect(row?.textContent).toContain('scanning')
    expect(row?.textContent).toContain('masked_paths incomplete')
    expect(row?.textContent).not.toContain('snap-1')
    expect(container.innerHTML).not.toContain('snap-1')
  })

  it('no runs at all: says so instead of drawing an empty list', () => {
    const { container } = mount(
      'quiet',
      (input) => {
        input.page.facts.kind = 'scanner'
      },
      { runs: [] },
    )
    expect(container.querySelector('.runs')).toBeNull()
    expect([...container.querySelectorAll('.scan-col .none')].some((n) => n.textContent?.includes('No scan has been ordered'))).toBe(
      true,
    )
  })
})
