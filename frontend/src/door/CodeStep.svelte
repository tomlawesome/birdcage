<script lang="ts">
  // The second step of a sign-in: an authenticator code, a recovery
  // code or a passkey, whichever the server listed (a recovery code is
  // always accepted). Switching between them is this screen's own state;
  // the pending-login cookie carries the sign-in whichever is used.
  import { onMount, tick, untrack } from 'svelte'
  import { sendJSON } from '../lib/api'
  import { readLoginReply } from '../lib/auth'
  import { CeremonyError, getAssertion } from '../lib/webauthn'
  import Alert from './Alert.svelte'
  import { ENTER_APP_CODE, ENTER_RECOVERY_CODE, FAILED, INCORRECT_CODE, kindOf, statusOf, TOO_MANY, type Message } from './messages'

  let {
    methods,
    onaccount,
    ontimedout,
  }: {
    methods: string[]
    onaccount: () => void
    /** The pending login is gone: sign in again from the start. */
    ontimedout: () => void
  } = $props()

  type Mode = 'totp' | 'recovery' | 'passkey'
  const hasTotp = $derived(methods.includes('totp'))
  const hasPasskey = $derived(methods.includes('passkey'))
  let mode: Mode = $state(untrack(() => (methods.includes('totp') ? 'totp' : methods.includes('passkey') ? 'passkey' : 'recovery')))
  // A sign-in held for a passkey after its code (`prove`): finished with
  // the prove routes, and nothing else is offered.
  let prove = $state(false)

  let code = $state('')
  let busy = $state(false)
  let prompting = $state(false)
  let msg: Message | null = $state(null)
  let codeEl: HTMLInputElement | undefined = $state()

  const subtitle = $derived(
    mode === 'passkey'
      ? 'Your password was right. Use your passkey to finish signing in.'
      : mode === 'recovery'
        ? 'Your password was right. Enter one of your recovery codes to finish signing in.'
        : 'Your password was right. Enter the current code from your authenticator app to finish signing in.',
  )

  onMount(() => codeEl?.focus({ preventScroll: true }))

  async function switchTo(next: Mode) {
    mode = next
    msg = null
    code = ''
    await tick()
    codeEl?.focus({ preventScroll: true })
  }

  function refused(err: unknown) {
    if (statusOf(err) === 401 && kindOf(err) === 'step-expired') ontimedout()
    else if (statusOf(err) === 429) msg = { text: TOO_MANY }
    else msg = { text: FAILED }
  }

  async function submitCode(e: Event) {
    e.preventDefault()
    if (busy || mode === 'passkey') return
    if (!code) return void (msg = { text: mode === 'recovery' ? ENTER_RECOVERY_CODE : ENTER_APP_CODE })
    busy = true
    msg = null
    try {
      const reply = readLoginReply(await sendJSON('POST', '/api/auth/login/factor', { code }))
      if (reply.kind === 'account') onaccount()
      else if (reply.kind === 'prove') {
        prove = true
        mode = 'passkey'
        code = ''
      } else msg = { text: FAILED }
    } catch (err) {
      if (statusOf(err) === 401 && kindOf(err) === 'invalid-credentials') {
        msg = { text: INCORRECT_CODE }
        code = ''
        await tick()
        codeEl?.focus()
      } else refused(err)
    } finally {
      busy = false
    }
  }

  async function usePasskey() {
    if (busy) return
    busy = true
    msg = null
    const [begin, finish] = prove ? ['/api/auth/login/prove/begin', '/api/auth/login/prove'] : ['/api/auth/login/factor/begin', '/api/auth/login/factor']
    let finishing = false
    try {
      const options = await sendJSON('POST', begin)
      prompting = true
      const assertion = await getAssertion(options).finally(() => (prompting = false))
      finishing = true
      const reply = readLoginReply(await sendJSON('POST', finish, { assertion }))
      if (reply.kind === 'account') onaccount()
      else msg = { text: FAILED }
    } catch (err) {
      // A cancelled prompt, or a refused or dead ceremony at the finish:
      // the next press begins a fresh one. A pending login that has gone
      // says so at begin, and that is the timed-out case.
      if (err instanceof CeremonyError || (finishing && statusOf(err) === 401)) msg = { text: FAILED }
      else refused(err)
    } finally {
      busy = false
    }
  }
</script>

<form class="f-code" novalidate onsubmit={submitCode}>
  <h1>{mode === 'passkey' ? 'Use your passkey' : 'Enter your code'}</h1>
  <p class="subtitle">{subtitle}</p>
  {#if mode === 'passkey'}
    <Alert {msg} />
    <button type="button" class="submit" disabled={busy} onclick={usePasskey}
      >{prompting ? 'Waiting…' : busy ? 'Please wait…' : 'Use your passkey'}</button
    >
  {:else}
    <label
      ><span class="sr-only">{mode === 'recovery' ? 'Recovery code' : 'Code'}</span><input
        bind:this={codeEl}
        bind:value={code}
        class:code-field={mode === 'totp'}
        inputmode={mode === 'totp' ? 'numeric' : 'text'}
        maxlength={mode === 'totp' ? 6 : undefined}
        placeholder={mode === 'recovery' ? 'recovery code' : '6-digit code'}
        autocomplete="one-time-code"
      /></label
    >
    <Alert {msg} />
    <button class="submit" disabled={busy}>{busy ? 'Please wait…' : 'Continue'}</button>
  {/if}
  {#if !prove}
    {#if mode !== 'passkey' && hasPasskey}
      <button type="button" class="link" onclick={() => switchTo('passkey')}>Use your passkey instead</button>
    {/if}
    {#if mode !== 'totp' && hasTotp}
      <button type="button" class="link" onclick={() => switchTo('totp')}>Use your authenticator app instead</button>
    {/if}
    {#if mode !== 'recovery'}
      <button type="button" class="link" onclick={() => switchTo('recovery')}>Use a recovery code instead</button>
    {/if}
  {/if}
</form>
