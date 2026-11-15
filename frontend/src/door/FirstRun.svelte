<script lang="ts">
  // First run: the admin account, made with the setup code the server
  // wrote to its log.
  import { onMount } from 'svelte'
  import { sendJSON } from '../lib/api'
  import Alert from './Alert.svelte'
  import {
    CONFIRM_PASSWORD,
    detailOf,
    ENTER_ACCOUNT,
    ENTER_PASSWORD,
    FAILED,
    MISMATCH,
    statusOf,
    TOO_MANY,
    type Message,
  } from './messages'

  let {
    oncreated,
    onconflict,
  }: {
    /** Created and signed in: the password, for the second step owed next. */
    oncreated: (password: string) => void
    /** An account exists already: carry on by the session. */
    onconflict: () => void
  } = $props()

  let setupCode = $state('')
  let username = $state('')
  let password = $state('')
  let confirm = $state('')
  let busy = $state(false)
  let msg: Message | null = $state(null)
  let setupEl: HTMLInputElement | undefined = $state()

  onMount(() => setupEl?.focus({ preventScroll: true }))

  function check(): string | null {
    if (!setupCode) return 'Enter the setup code.'
    if (!username) return ENTER_ACCOUNT
    if (!password) return ENTER_PASSWORD
    if (!confirm) return CONFIRM_PASSWORD
    if (password !== confirm) return MISMATCH
    return null
  }

  async function submit(e: Event) {
    e.preventDefault()
    if (busy) return
    const problem = check()
    if (problem) return void (msg = { text: problem })
    busy = true
    msg = null
    try {
      await sendJSON('POST', '/api/auth/register', { username, password, setupCode })
      oncreated(password)
    } catch (err) {
      const status = statusOf(err)
      if (status === 401) msg = { text: 'Incorrect setup code.' }
      else if (status === 400) msg = { text: detailOf(err) || FAILED }
      else if (status === 409) onconflict()
      else if (status === 429) msg = { text: TOO_MANY }
      else msg = { text: FAILED }
    } finally {
      busy = false
    }
  }
</script>

<form class="f-firstrun f-wide" novalidate onsubmit={submit}>
  <h1>Create the admin account</h1>
  <p class="subtitle">No account exists yet. The setup code is in the server log.</p>
  <label
    ><span class="sr-only">Setup code</span><input bind:this={setupEl} bind:value={setupCode} placeholder="setup code" autocomplete="off" /></label
  >
  <label><span class="sr-only">Account</span><input bind:value={username} placeholder="account" autocomplete="username" /></label>
  <label
    ><span class="sr-only">Password</span><input
      bind:value={password}
      type="password"
      placeholder="password"
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
  <button class="submit" disabled={busy}>{busy ? 'Please wait…' : 'Create account'}</button>
</form>
