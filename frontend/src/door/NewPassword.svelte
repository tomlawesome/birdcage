<script lang="ts">
  // Set a new password: mikroview's forced-change screen (#1251 there),
  // on the same door. The person is signed in already, with a one-time
  // code, so there is no account to name.
  import { onMount } from 'svelte'
  import { sendJSON } from '../lib/api'
  import Alert from './Alert.svelte'
  import { CONFIRM_PASSWORD, detailOf, ENTER_PASSWORD, FAILED, MISMATCH, SIGN_IN_AS_SOMEONE_ELSE, statusOf, TOO_MANY, type Message } from './messages'

  /** Busy until the promise onchanged returns settles. */
  let {
    onchanged,
    onsignin,
  }: {
    onchanged: (password: string) => void | Promise<void>
    /** Signed out: the full sign-in. */
    onsignin: () => void
  } = $props()

  let password = $state('')
  let confirm = $state('')
  let busy = $state(false)
  let msg: Message | null = $state(null)
  let firstEl: HTMLInputElement | undefined = $state()

  onMount(() => firstEl?.focus({ preventScroll: true }))

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

  async function submit(e: Event) {
    e.preventDefault()
    if (busy) return
    if (!password) return void (msg = { text: ENTER_PASSWORD })
    if (!confirm) return void (msg = { text: CONFIRM_PASSWORD })
    if (password !== confirm) return void (msg = { text: MISMATCH })
    busy = true
    msg = null
    try {
      await sendJSON('POST', '/api/auth/password', { newPassword: password })
      await onchanged(password)
    } catch (err) {
      const status = statusOf(err)
      if (status === 400) msg = { text: detailOf(err) || FAILED }
      else if (status === 429) msg = { text: TOO_MANY }
      else msg = { text: FAILED }
    } finally {
      busy = false
    }
  }
</script>

<form class="f-newpassword f-wide" novalidate onsubmit={submit}>
  <h1>Set a new password</h1>
  <p class="subtitle">Your one-time code got you in. Choose a password only you know.</p>
  <label
    ><span class="sr-only">New password</span><input
      bind:this={firstEl}
      bind:value={password}
      type="password"
      placeholder="new password"
      autocomplete="new-password"
    /></label
  >
  <label
    ><span class="sr-only">Confirm password</span><input
      bind:value={confirm}
      type="password"
      placeholder="confirm password"
      autocomplete="new-password"
    /></label
  >
  <Alert {msg} />
  <button class="submit" disabled={busy}>{busy ? 'Please wait…' : 'Set password'}</button>
  <button type="button" class="link" disabled={busy} onclick={someoneElse}>{SIGN_IN_AS_SOMEONE_ELSE}</button>
</form>
