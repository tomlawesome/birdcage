<script lang="ts">
  // Session expired, over the dimmed dashboard: the timed-out session is
  // resumed with the password (or a passkey, when passkey sign-in is on),
  // keeping its original sign-in time.
  import { onMount, tick } from 'svelte'
  import { sendJSON } from '../lib/api'
  import type { SessionState } from '../lib/auth'
  import { CeremonyError, getAssertion } from '../lib/webauthn'
  import Alert from './Alert.svelte'
  import { ENTER_PASSWORD, FAILED, INCORRECT_PASSWORD, kindOf, statusOf, tooMany, type Message } from './messages'

  let {
    session,
    onresumed,
    onsignin,
  }: {
    session: SessionState
    onresumed: () => void
    /** Nothing to resume, or someone else: the full sign-in. */
    onsignin: () => void
  } = $props()

  let passkey = $state(false)
  let password = $state('')
  let busy = $state(false)
  let prompting = $state(false)
  let msg: Message | null = $state(null)
  let passwordEl: HTMLInputElement | undefined = $state()

  onMount(() => passwordEl?.focus({ preventScroll: true }))

  function refused(err: unknown) {
    if (statusOf(err) === 401 && kindOf(err) === 'sign-in-required') onsignin()
    else if (statusOf(err) === 429) msg = tooMany(session.ssoAvailable)
    else msg = { text: FAILED }
  }

  async function submit(e: Event) {
    e.preventDefault()
    if (busy || passkey) return
    if (!password) return void (msg = { text: ENTER_PASSWORD })
    busy = true
    msg = null
    try {
      await sendJSON('POST', '/api/auth/reauthenticate', { password })
      onresumed()
    } catch (err) {
      if (statusOf(err) === 401 && kindOf(err) === 'invalid-credentials') {
        msg = { text: INCORRECT_PASSWORD }
        password = ''
        await tick()
        passwordEl?.focus()
      } else refused(err)
    } finally {
      busy = false
    }
  }

  async function usePasskey() {
    if (busy) return
    busy = true
    msg = null
    try {
      const options = await sendJSON('POST', '/api/auth/login/passkey/begin')
      prompting = true
      const assertion = await getAssertion(options).finally(() => (prompting = false))
      await sendJSON('POST', '/api/auth/reauthenticate', { assertion })
      onresumed()
    } catch (err) {
      if (err instanceof CeremonyError) msg = { text: FAILED }
      else refused(err)
    } finally {
      busy = false
    }
  }

  async function someoneElse() {
    if (busy) return
    busy = true
    try {
      await sendJSON('POST', '/api/auth/logout')
    } catch {
      // Signed out or not, the full sign-in is what comes next.
    } finally {
      busy = false
    }
    onsignin()
  }
</script>

<form class="f-expired f-wide" novalidate onsubmit={submit}>
  <h1>{passkey ? 'Use your passkey' : 'Session expired'}</h1>
  {#if !passkey}
    <p class="subtitle">Enter your password to continue.</p>
    {#if session.username}<p class="who">{session.username}</p>{/if}
    <label
      ><span class="sr-only">Password</span><input
        bind:this={passwordEl}
        bind:value={password}
        type="password"
        placeholder="password"
        autocomplete="current-password"
      /></label
    >
    <Alert {msg} />
    <button class="submit" disabled={busy}>{busy ? 'Please wait…' : 'Continue'}</button>
    {#if session.passkeys?.signIn}
      <button type="button" class="link" onclick={() => ((passkey = true), (msg = null))}>Use your passkey instead</button>
    {/if}
  {:else}
    <Alert {msg} />
    <button type="button" class="submit" disabled={busy} onclick={usePasskey}
      >{prompting ? 'Waiting…' : busy ? 'Please wait…' : 'Use your passkey'}</button
    >
  {/if}
  <button type="button" class="link" onclick={someoneElse}>Sign in as someone else</button>
</form>
