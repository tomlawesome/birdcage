<script lang="ts">
  // Set a new password: mikroview's forced-change screen (#1251 there),
  // on the same door. The person is signed in already, with a one-time
  // code, so there is no account to name.
  import { onMount } from 'svelte'
  import { sendJSON } from '../lib/api'
  import Alert from './Alert.svelte'
  import { CONFIRM_PASSWORD, detailOf, ENTER_PASSWORD, FAILED, MISMATCH, statusOf, TOO_MANY, type Message } from './messages'

  let { onchanged }: { onchanged: (password: string) => void } = $props()

  let password = $state('')
  let confirm = $state('')
  let busy = $state(false)
  let msg: Message | null = $state(null)
  let firstEl: HTMLInputElement | undefined = $state()

  onMount(() => firstEl?.focus({ preventScroll: true }))

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
      onchanged(password)
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
</form>
