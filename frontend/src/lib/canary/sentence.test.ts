import { describe, expect, it } from 'vitest'
import { plainText } from '../sentence/types'
import { sceneInput } from './fixtures'
import { canaryActions, canaryCrumb, canaryFooter, canaryScene, canarySentence, selfTestHeading } from './sentence'

const text = (scene: Parameters<typeof sceneInput>[0]) => {
  const s = canarySentence(sceneInput(scene))
  return { hero: plainText(s.hero), sub: plainText(s.sub) }
}

describe('canaryScene: which rule speaks', () => {
  it('a still-arriving sweep outranks the canary\'s own state', () => {
    const input = sceneInput('night')
    input.page.canary.status = 'silent'
    input.page.canary.silent_for_s = 300
    expect(canaryScene(input).kind).toBe('visited')
  })

  it('a state outranks a visit that has finished', () => {
    const input = sceneInput('night')
    for (const v of input.visitors) v.still_arriving = false
    input.page.canary.status = 'self_test_failed'
    expect(canaryScene(input)).toEqual({ kind: 'state', status: 'self_test_failed' })
  })

  it('an untouched, healthy canary is quiet', () => {
    expect(canaryScene(sceneInput('quiet')).kind).toBe('quiet')
  })
})

describe('the four round-7 scenes', () => {
  it('quiet: it was enrolled, it phones home, and the self-test reached everything', () => {
    const { hero, sub } = text('quiet')
    expect(hero).toBe('canary-iot is quiet, and answers when tested.')
    expect(sub).toContain('enrolled on Wed 12 Aug')
    expect(sub).toContain('It phones home every minute')
    expect(sub).toContain('self-test at 04:00 reached all four of its services')
    expect(sub).toContain('Two short silences this week, both over in minutes.')
  })

  it('failed: names what did not answer, and what did', () => {
    const { hero, sub } = text('failed')
    expect(hero).toBe('canary-iot is phoning home — but deaf on telnet.')
    expect(sub).toContain('self-test at 04:00 reached ssh, smb and the portscan lure')
    expect(sub).toContain('telnet :23 did not answer')
    expect(sub).toContain('the next scheduled run is 04:00 tomorrow.')
  })

  it('silent: counts the run of silences, oldest first, and says what it means', () => {
    const { hero, sub } = text('silent')
    expect(hero).toBe('canary-iot is silent — the third time this week.')
    expect(sub).toContain('Its last heartbeat was 21:58:19, six minutes ago.')
    expect(sub).toContain('It also dropped out on Tue 1 Sep for eleven minutes and on Thu 3 Sep for one')
    expect(sub).toContain('Three silences in five days is not a bad minute')
  })

  it('night: the visit, the repeat underneath it, and where to act', () => {
    const { hero, sub } = text('night')
    expect(hero).toBe('canary-iot was swept at 22:01, and is still being knocked on.')
    expect(sub).toContain('203.0.113.42 tried root / toor on telnet at 22:01')
    expect(sub).toContain('the same address that walked all four canaries tonight')
    expect(sub).toContain('198.51.100.7 has knocked on :445 every twenty minutes for six nights')
    expect(sub).toContain('Nothing here blocks: lookback in mikroview ▸ to act.')
  })

  it('a single silence is a bad minute, not a pattern', () => {
    const input = sceneInput('silent')
    input.history!.periods = input.history!.periods.filter((p) => p.ended_at === null)
    const sub = plainText(canarySentence(input).sub)
    expect(sub).toContain('A silent agent is not the quiet we want')
    expect(sub).not.toContain('is not a bad minute')
  })
})

// ADR-0012 Part B (issue #130): the canary page's own copy of the two
// new health states, same slot 'self_test_failed' above already proves
// out (a finished visit loses to the canary's own state).
describe('credential_conflict and renewal_stalled (ADR-0012 Part B)', () => {
  it('credential_conflict outranks a finished visit, same as any other state', () => {
    const input = sceneInput('night')
    for (const v of input.visitors) v.still_arriving = false
    input.page.canary.status = 'credential_conflict'
    expect(canaryScene(input)).toEqual({ kind: 'state', status: 'credential_conflict' })
  })

  it('credential_conflict: names the two addresses and the revoke action', () => {
    const input = sceneInput('night')
    for (const v of input.visitors) v.still_arriving = false
    input.page.canary.status = 'credential_conflict'
    input.page.canary.credential_conflict = { addresses: ['10.0.0.1', '10.0.0.2'] }
    const { hero, sub } = { hero: plainText(canarySentence(input).hero), sub: plainText(canarySentence(input).sub) }
    expect(hero).toBe("canary-iot's credential is live in two places at once.")
    expect(sub).toContain('credential in use from two addresses: 10.0.0.1 and 10.0.0.2.')
    expect(sub).toContain('Revoke the node (birdcage agent revoke <agent-id>) and re-enrol it.')
  })

  it('credential_conflict: names the two build versions when only they are sent', () => {
    const input = sceneInput('night')
    for (const v of input.visitors) v.still_arriving = false
    input.page.canary.status = 'credential_conflict'
    input.page.canary.credential_conflict = { versions: ['1.0.0', '0.9.9'] }
    const sub = plainText(canarySentence(input).sub)
    expect(sub).toContain('credential in use from two builds: 1.0.0 and 0.9.9.')
  })

  it('credential_conflict: bare sentence when neither addresses nor versions are sent', () => {
    const input = sceneInput('night')
    for (const v of input.visitors) v.still_arriving = false
    input.page.canary.status = 'credential_conflict'
    const sub = plainText(canarySentence(input).sub)
    expect(sub).toContain('Its credential is in use from two places at once.')
  })

  it('not_delivering: certificate expired names that cause instead of the log read', () => {
    const input = sceneInput('night')
    for (const v of input.visitors) v.still_arriving = false
    input.page.canary.status = 'not_delivering'
    input.page.canary.certificate_expired = true
    const sub = plainText(canarySentence(input).sub)
    expect(sub).toContain('Its certificate expired before it renewed, so it can no longer authenticate to birdcage')
    expect(sub).not.toContain("can't read OpenCanary's log")
  })

  it('renewal_stalled: not yet escalated names the certificate past its renewal point', () => {
    const input = sceneInput('night')
    for (const v of input.visitors) v.still_arriving = false
    input.page.canary.status = 'renewal_stalled'
    input.page.canary.renewal_stalled_for_s = 300
    input.page.canary.renewal_stalled_escalated = false
    const sub = plainText(canarySentence(input).sub)
    expect(sub).toContain('Its certificate passed its renewal point five minutes ago')
    expect(sub).toContain("Check the agent can reach birdcage's ingest listener.")
  })

  it('renewal_stalled: escalated claims only what both triggers make true', () => {
    const input = sceneInput('night')
    for (const v of input.visitors) v.still_arriving = false
    input.page.canary.status = 'renewal_stalled'
    input.page.canary.renewal_stalled_escalated = true
    const sub = plainText(canarySentence(input).sub)
    expect(sub).toContain("It hasn't renewed its certificate in over a day past its renewal point.")
    expect(sub).not.toContain('passed its renewal point')
  })

  it('the crumb and footer name both new states via the shared stateWords voice', () => {
    const input = sceneInput('night')
    for (const v of input.visitors) v.still_arriving = false
    input.page.canary.status = 'credential_conflict'
    input.page.canary.credential_conflict = { addresses: ['10.0.0.1', '10.0.0.2'] }
    expect(plainText(canaryCrumb(input))).toContain('credential conflict')
    expect(plainText(canaryFooter(input))).toContain('credential conflict')
  })
})

// issue #132 / #45 / #116: three statuses the fleet-level rules already
// handle (rule2OpenCanaryDown, rule2HitsMerged, rule2DbStale) had no
// case on the canary's own page, so they fell through to the 'pending'
// default instead of naming the actual state.
describe('opencanary_down, hits_merged and db_stale on the canary page', () => {
  it('opencanary_down: names the down honeypot, not "pending"', () => {
    const input = sceneInput('night')
    for (const v of input.visitors) v.still_arriving = false
    input.page.canary.status = 'opencanary_down'
    const { hero, sub } = { hero: plainText(canarySentence(input).hero), sub: plainText(canarySentence(input).sub) }
    expect(hero).toBe("canary-iot's OpenCanary is not answering.")
    expect(sub).toContain('Check OpenCanary on the box.')
    expect(sub).not.toContain('pending its first self-test')
  })

  it('hits_merged: names the merged hit count', () => {
    const input = sceneInput('night')
    for (const v of input.visitors) v.still_arriving = false
    input.page.canary.status = 'hits_merged'
    input.page.canary.event_id_collisions = 2
    const { hero, sub } = { hero: plainText(canarySentence(input).hero), sub: plainText(canarySentence(input).sub) }
    expect(hero).toBe('canary-iot merged two hits.')
    expect(sub).toContain('check its clock, that only one OpenCanary runs, and that the log rotates by rename.')
  })

  it('db_stale: names the hours the database refresh has been failing', () => {
    const input = sceneInput('night')
    for (const v of input.visitors) v.still_arriving = false
    input.page.canary.status = 'db_stale'
    input.page.canary.db_refresh = { failing_since: '2026-09-11T16:04:31Z', last_error: 'timeout' }
    const { hero, sub } = { hero: plainText(canarySentence(input).hero), sub: plainText(canarySentence(input).sub) }
    expect(hero).toBe("canary-iot's vulnerability database has gone stale.")
    expect(sub).toContain('30 hours')
    expect(sub).toContain('Check the scanner can reach the vulnerability database mirror.')
  })

  it('the crumb and footer name all three via the shared stateWords voice', () => {
    const opencanaryDown = sceneInput('night')
    for (const v of opencanaryDown.visitors) v.still_arriving = false
    opencanaryDown.page.canary.status = 'opencanary_down'
    expect(plainText(canaryCrumb(opencanaryDown))).toContain('OpenCanary not answering')
    expect(plainText(canaryFooter(opencanaryDown))).toContain('OpenCanary not answering')

    const hitsMerged = sceneInput('night')
    for (const v of hitsMerged.visitors) v.still_arriving = false
    hitsMerged.page.canary.status = 'hits_merged'
    expect(plainText(canaryCrumb(hitsMerged))).toContain('hits merged')
    expect(plainText(canaryFooter(hitsMerged))).toContain('hits merged')

    const dbStale = sceneInput('night')
    for (const v of dbStale.visitors) v.still_arriving = false
    dbStale.page.canary.status = 'db_stale'
    expect(plainText(canaryCrumb(dbStale))).toContain('vulnerability database stale')
    expect(plainText(canaryFooter(dbStale))).toContain('vulnerability database stale')
  })
})

describe('canaryCrumb', () => {
  it('ends in the clock when nothing is wrong', () => {
    expect(plainText(canaryCrumb(sceneInput('quiet')))).toBe('the cage › canary-iot · sat 5 sep · 22:04:31')
  })

  it('ends in the state when something is', () => {
    expect(plainText(canaryCrumb(sceneInput('silent')))).toBe('the cage › canary-iot · sat 5 sep · silent 6 m 12 s')
    expect(plainText(canaryCrumb(sceneInput('failed')))).toBe('the cage › canary-iot · sat 5 sep · self-test failed')
  })

  it('counts the flags and this canary\'s own hits on a live night', () => {
    expect(plainText(canaryCrumb(sceneInput('night')))).toMatch(/^the cage › canary-iot · sat 12 sep · 1 flagged · \d+ hits today$/)
  })
})

describe('canaryFooter', () => {
  it('closes each scene in its own words', () => {
    expect(plainText(canaryFooter(sceneInput('quiet')))).toBe(
      'twenty-four days on the iot lane · answers when tested · nothing to act on',
    )
    expect(plainText(canaryFooter(sceneInput('failed')))).toContain('deaf on one port')
    expect(plainText(canaryFooter(sceneInput('silent')))).toBe(
      'three silences in five days — silence is only good news while the heartbeat keeps coming',
    )
    expect(plainText(canaryFooter(sceneInput('night')))).toContain('the address walking the cage reached this one too')
  })
})

describe('canaryActions: only the ones the state earns', () => {
  it('quiet offers the self-test and maintenance, and nothing to look back at', () => {
    expect(canaryActions(sceneInput('quiet')).map((a) => a.label)).toEqual([
      'run the self-test now ▸',
      'mark as maintenance',
    ])
  })

  it('a failed self-test earns the lookback too', () => {
    expect(canaryActions(sceneInput('failed')).map((a) => a.label)).toEqual([
      'run the self-test now ▸',
      'lookback in mikroview ▸',
      'mark as maintenance',
    ])
  })

  it('a silent canary is not offered a probe it cannot answer', () => {
    const labels = canaryActions(sceneInput('silent')).map((a) => a.label)
    expect(labels).not.toContain('run the self-test now ▸')
    expect(labels).toEqual(['lookback in mikroview ▸', 'mark as maintenance'])
  })

  it('a live visit leads with the lookback and the raw lines', () => {
    const actions = canaryActions(sceneInput('night'))
    expect(actions.map((a) => a.label)).toEqual(['lookback in mikroview ▸', 'raw lines ▸', 'run the self-test now'])
    expect(actions[2].quiet).toBe(true)
  })
})

describe('selfTestHeading', () => {
  it('says when, the verdict and the counts', () => {
    const heading = selfTestHeading(sceneInput('quiet'))
    expect(heading.lead).toBe('self-test · today 04:00:07 · ')
    expect(heading.verdict).toEqual({ text: 'passed', cls: 'ok' })
    expect(heading.tail).toBe(' · 4 of 4')
    expect(heading.note).toBe('')
  })

  it('a failed run counts what did answer', () => {
    const heading = selfTestHeading(sceneInput('failed'))
    expect(heading.verdict).toEqual({ text: 'failed', cls: 'r' })
    expect(heading.tail).toBe(' · 3 of 4')
  })

  it('adds the note when the canary went silent after the last run', () => {
    expect(selfTestHeading(sceneInput('silent')).note).toBe('no run since it went silent')
  })

  it('says so when nothing has ever run', () => {
    const input = sceneInput('quiet')
    input.page.self_test_runs = []
    expect(selfTestHeading(input).verdict).toEqual({ text: 'never run', cls: 'r' })
  })
})

// Issue #54: the canary page's own words for an agent behind birdcage,
// and for the upgrade window an accepted upgrade token opens.
describe('issue #54 scenes', () => {
  it('agent out of date: points at the facts column for the upgrade command', () => {
    const { hero, sub } = text('agentOutOfDate')
    expect(hero).toBe("canary-iot's agent has fallen behind.")
    expect(sub).toContain('It is running 0.1.0; birdcage is on 0.1.1.')
    expect(sub).toContain('Get its upgrade command as shown below.')
  })

  it('upgrade in progress: says when the old agent has to be gone by, in the hero, sub and crumb', () => {
    const input = sceneInput('upgradeInProgress')
    const s = canarySentence(input)
    expect(plainText(s.hero)).toBe('canary-iot is being upgraded.')
    expect(plainText(s.sub)).toBe(
      'The old agent has until 09:18 to go offline. Until then, the old and new builds both reporting on this ' +
        'credential is expected, not a credential conflict; after it, detection is back to normal.',
    )
    expect(plainText(canaryCrumb(input))).toBe('the cage › canary-iot · sun 20 sep · upgrade in progress until 09:18')
  })

  it('upgrade in progress without a window end still reads', () => {
    const input = sceneInput('upgradeInProgress')
    delete input.page.canary.upgrade_window_until
    expect(plainText(canarySentence(input).sub)).toContain('The old agent has a few minutes to go offline.')
    expect(plainText(canaryCrumb(input))).toContain('· upgrade in progress')
  })
})
