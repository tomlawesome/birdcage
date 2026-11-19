<script lang="ts">
  // The sign-in door (issue #8, ADR-0017): mikroview's door between cage
  // bars. Shows the screen doorFor(session) names and moves between the
  // screens as docs/design/sign-in-screens.md describes. After every step
  // that could finish signing in it reads the session again, and calls
  // onenter once the server says the account is signed in with nothing
  // owed.
  //
  // The password typed during this visit is held here, in memory only,
  // so a second step owed straight after signing in does not ask for it
  // again. It is dropped as soon as it cannot be needed: on the way back
  // to sign in, and on entering.
  //
  // Each screen awaits the promise proceed() returns, so it stays busy
  // (and a second submit sends nothing) until the session has been read
  // again; and proceed() itself runs one read at a time and enters once.
  import { untrack } from 'svelte'
  import { doorFor, readSession, type SessionState } from '../lib/auth'
  import Bars from './Bars.svelte'
  import CodeStep from './CodeStep.svelte'
  import Expired from './Expired.svelte'
  import FirstRun from './FirstRun.svelte'
  import NewPassword from './NewPassword.svelte'
  import SecondStep from './SecondStep.svelte'
  import SignIn from './SignIn.svelte'
  import { FAILED, TIMED_OUT, type Message } from './messages'
  import './door.css'

  let {
    session,
    onenter,
    leaving = false,
    frozenAt,
  }: {
    session: SessionState
    /** Signed in with nothing owed; given the session that says so.
     * Called at most once. */
    onenter: (session: SessionState) => void
    /** The door is opening onto the dashboard: the bars slide apart. */
    leaving?: boolean
    /** Draw the bars still, this many seconds in (the pixel gate). */
    frozenAt?: number
  } = $props()

  type Screen = 'signin' | 'code' | 'firstrun' | 'choose' | 'newpassword' | 'expired' | 'in'
  let current: SessionState = $state(untrack(() => session))
  let screen: Screen = $state(untrack(() => doorFor(session)))
  let held = $state('')
  let methods: string[] = $state([])
  // ?ssoError is read only when the door opens on sign in.
  let notice: Message | null = $state(untrack(() => (doorFor(session) === 'signin' ? ssoNotice() : null)))
  // Each new arrival at a screen remounts it, so it starts clean.
  let visit = $state(0)

  /** ?ssoError=<code> from the SSO callback: shown once, then removed
   * from the address (other parameters stay). */
  function ssoNotice(): Message | null {
    if (typeof location === 'undefined') return null
    const q = new URLSearchParams(location.search)
    const code = q.get('ssoError')
    if (code === null) return null
    q.delete('ssoError')
    const rest = q.toString()
    history.replaceState(history.state, '', location.pathname + (rest ? '?' + rest : '') + location.hash)
    return {
      text:
        code === 'not_permitted'
          ? 'Your account signed in but is not permitted to use this birdcage.'
          : 'SSO sign-in failed. Try again, or sign in with your password.',
    }
  }

  function go(next: Screen, why: Message | null = null) {
    if (next === 'signin') held = ''
    notice = why
    screen = next
    visit++
  }

  let reading: Promise<void> | null = null
  let entered = false

  /** Re-read the session and continue by it. A call while a read is in
   * flight shares it; after entering, nothing more happens. */
  function proceed(): Promise<void> {
    if (entered) return Promise.resolve()
    reading ??= (async () => {
      let s: SessionState
      try {
        s = await readSession()
      } catch {
        return go('signin', { text: FAILED })
      }
      current = s
      const next = doorFor(s)
      if (next === 'in') {
        entered = true
        held = ''
        screen = 'in'
        onenter(s)
      } else go(next)
    })().finally(() => (reading = null))
    return reading
  }

  const keep = (pw: string) => (held = pw)
</script>

<div class="door" data-state={screen} class:leaving>
  <div class="screen">
    <Bars {frozenAt} opening={() => leaving} />
    <div class="stack">
      <div class="wm-box"><span class="wm">BIRD<em>CAGE</em></span></div>
      {#key visit}
        {#if screen === 'signin'}
          <SignIn
            ssoAvailable={current.ssoAvailable}
            {notice}
            onaccount={(pw) => (keep(pw), proceed())}
            onsecondfactor={(list, pw) => ((methods = list), keep(pw), go('code'))}
          />
        {:else if screen === 'code'}
          <CodeStep {methods} onaccount={proceed} ontimedout={() => go('signin', { text: TIMED_OUT })} />
        {:else if screen === 'firstrun'}
          <FirstRun oncreated={(pw) => (keep(pw), proceed())} onconflict={proceed} />
        {:else if screen === 'choose'}
          <SecondStep session={current} password={held} onpassword={keep} ondone={proceed} onsignin={() => go('signin')} />
        {:else if screen === 'newpassword'}
          <NewPassword onchanged={(pw) => (keep(pw), proceed())} onsignin={() => go('signin')} />
        {:else if screen === 'expired'}
          <Expired session={current} onresumed={proceed} onsignin={() => go('signin')} />
        {/if}
      {/key}
    </div>
  </div>
</div>
