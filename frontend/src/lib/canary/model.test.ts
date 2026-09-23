import { describe, expect, it } from 'vitest'
import { sceneInput } from './fixtures'
import { lastCompletedRun, listeningServices, periodsHere, selfTestCards, silences, traceOf, visitorsHere } from './model'

describe('selfTestCards', () => {
  it('lists the listening services first, in the tile\'s own order, then the lures', () => {
    const cards = selfTestCards(sceneInput('quiet').page.canary)
    expect(cards.map((c) => c.service)).toEqual(['telnet', 'ssh', 'smb', 'portscan'])
    expect(cards.map((c) => c.lure)).toEqual([false, false, false, true])
    expect(cards.map((c) => c.port)).toEqual(['23', '22', '445', null])
  })

  it('carries the run\'s verdict and grade per service', () => {
    const cards = selfTestCards(sceneInput('failed').page.canary)
    const telnet = cards.find((c) => c.service === 'telnet')!
    const portscan = cards.find((c) => c.service === 'portscan')!
    expect(telnet.outcome).toBe('failed')
    expect(portscan.outcome).toBe('passed')
    expect(portscan.grade).toBe('attributed')
  })

  it('a listening service the run never probed is untested, not failed', () => {
    const canary = sceneInput('quiet').page.canary
    canary.ports = `${canary.ports} · ntp 123`
    const ntp = selfTestCards(canary).find((c) => c.service === 'ntp')!
    expect(ntp.outcome).toBe('untested')
    expect(ntp.port).toBe('123')
  })

  it('is empty when no run has ever completed -- there is no ledger to draw', () => {
    const canary = sceneInput('quiet').page.canary
    canary.self_test = []
    expect(selfTestCards(canary)).toEqual([])
  })
})

describe('listeningServices', () => {
  it('reads the display string back into service names', () => {
    expect(listeningServices('telnet 23 · ssh 22 · smb 445')).toEqual(['telnet', 'ssh', 'smb'])
    expect(listeningServices('')).toEqual([])
  })
})

describe('narrowing to one canary', () => {
  it('finds this canary\'s trace row, its visitors and its periods', () => {
    const input = sceneInput('night')
    expect(traceOf(input)?.id).toBe('canary-iot')
    expect(visitorsHere(input).map((v) => v.source_ip)).toContain('203.0.113.42')
    expect(periodsHere(input).every((p) => p.canary_id === 'canary-iot')).toBe(true)
  })

  it('orders visitors newest last_at first', () => {
    const times = visitorsHere(sceneInput('night')).map((v) => Date.parse(v.last_at))
    expect([...times].sort((a, b) => b - a)).toEqual(times)
  })
})

describe('silences', () => {
  it('measures a closed silence from its own two ends', () => {
    const closed = silences(sceneInput('quiet'))
    expect(closed).toHaveLength(2)
    expect(closed.map((s) => s.seconds)).toEqual([60, 660])
    expect(closed.every((s) => !s.open)).toBe(true)
  })

  it('measures an open silence to now, and marks it open', () => {
    const open = silences(sceneInput('silent'))[0]
    expect(open.open).toBe(true)
    expect(open.endedAt).toBeNull()
    expect(open.seconds).toBe(372)
  })
})

describe('lastCompletedRun', () => {
  it('is the newest run with a completed_at', () => {
    const input = sceneInput('quiet')
    expect(lastCompletedRun(input.page.self_test_runs)?.issued_at).toBe(input.page.self_test_runs[0].issued_at)
  })

  it('is null when nothing has completed', () => {
    expect(lastCompletedRun([{ issued_at: '2026-09-05T04:00:00Z' }])).toBeNull()
  })
})
