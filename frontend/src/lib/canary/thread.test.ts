import { describe, expect, it } from 'vitest'
import { plainText } from '../sentence/types'
import { sceneInput } from './fixtures'
import { threadDuration, threadFooter, threadRows } from './thread'

const lines = (scene: Parameters<typeof sceneInput>[0]) =>
  threadRows(sceneInput(scene)).map((r) => `${r.when} | ${r.state} | ${plainText(r.detail)} | ${r.dot}`)

describe('threadDuration', () => {
  it('says minutes in words the tiles abbreviate, and stops at the largest unit past an hour', () => {
    expect(threadDuration(45)).toBe('45 s')
    expect(threadDuration(60)).toBe('1 min')
    expect(threadDuration(660)).toBe('11 min')
    expect(threadDuration(372)).toBe('6 min 12 s')
    expect(threadDuration(230)).toBe('3 min 50 s')
    expect(threadDuration(65044)).toBe('18 h')
    expect(threadDuration(200000)).toBe('2 d')
  })
})

describe('threadRows', () => {
  it('is newest first', () => {
    const ats = threadRows(sceneInput('silent')).map((r) => r.at)
    expect([...ats].sort((a, b) => b - a)).toEqual(ats)
  })

  it('quiet: the self-test, both silences, the last touch elsewhere, and how it was enrolled', () => {
    expect(lines('quiet')).toEqual([
      'today 04:00 | self-test passed | four of four services answered — telnet, ssh and smb marked, portscan attributed | ok',
      'thu 3 sep 07:12 | silent · 1 min | one heartbeat missed, back at 07:13 on its own | fault',
      'tue 1 sep 21:58 | silent · 11 min | eleven heartbeats missed, back at 22:09 on its own | fault',
      'thu 13 aug | quiet | the last thing that touched the cage was on canary-guest, not here | ok',
      'wed 12 aug 09:44 | registered | first self-test passed 3 min 50 s after enrolment | ok',
      'wed 12 aug 09:41 | enrolled | on iot, mockingbird 0.4.1 — pending its first self-test | pend',
    ])
  })

  it('an open silence is still true, and says so', () => {
    const top = threadRows(sceneInput('silent'))[0]
    expect(top.state).toBe('silent · 6 min 12 s')
    expect(plainText(top.detail)).toBe('six heartbeats missed so far. still silent')
    expect(top.dot).toBe('live')
  })

  it('a failed self-test carries how long it has been failing and that nothing has run since', () => {
    const top = threadRows(sceneInput('failed'))[0]
    expect(top.state).toBe('self-test failed · 18 h')
    expect(plainText(top.detail)).toBe('telnet :23 did not answer; ssh, smb and portscan did. still failing — no run since')
    expect(top.dot).toBe('live')
  })

  it('the last touch elsewhere is only told on the page that is otherwise untouched', () => {
    expect(lines('night').some((l) => l.includes('| quiet |'))).toBe(false)
    expect(lines('failed').some((l) => l.includes('| quiet |'))).toBe(false)
  })

  it('a visit names what was tried and whether it was part of a walk', () => {
    const swept = threadRows(sceneInput('night')).find((r) => r.state === 'swept')!
    expect(plainText(swept.detail)).toBe('203.0.113.42 tried root / toor on telnet — part of a walk across all four canaries')
  })

  it('a repeat visitor is counted, not listed', () => {
    const repeat = threadRows(sceneInput('night')).find((r) => r.state === 'repeat visitor')!
    expect(repeat.when).toBe('six nights')
    expect(plainText(repeat.detail)).toBe('198.51.100.7 knocks on :445 every ~20 min, 221 times in six nights')
  })
})

describe('threadFooter', () => {
  it('says the thread is complete rather than truncated', () => {
    expect(threadFooter(sceneInput('quiet'))).toBe('enrolled 24 days ago · nothing earlier')
    expect(threadFooter(sceneInput('night'))).toBe('enrolled 31 days ago · nothing earlier')
  })
})
