<script lang="ts">
  // Sign in (ADR-0017 decision 1): two underlined fields, the outlined
  // pill, then `or` and the SSO link when SSO is configured.
  import { onMount, tick } from 'svelte'
  import { sendJSON } from '../lib/api'
  import { readLoginReply } from '../lib/auth'
  import Alert from './Alert.svelte'
  import { ENTER_ACCOUNT, ENTER_PASSWORD, FAILED, kindOf, statusOf, tooMany, type Message } from './messages'

  let {
    ssoAvailable,
    notice = null,
    onaccount,
    onsecondfactor,
  }: {
    ssoAvailable: boolean
    /** A message carried in from elsewhere (an SSO error, a timed-out step). */
    notice?: Message | null
    /** Signed in by the password: the password, for a second step owed
     * next. Busy until the promise it returns settles. */
    onaccount: (password: string) => void | Promise<void>
    onsecondfactor: (methods: string[], password: string) => void
  } = $props()

  let username = $state('')
  let password = $state('')
  let busy = $state(false)
  let msg: Message | null = $state(null)
  let accountEl: HTMLInputElement | undefined = $state()
  let passwordEl: HTMLInputElement | undefined = $state()

  // door.js focuses the password; with no account typed yet, the account.
  onMount(() => accountEl?.focus({ preventScroll: true }))

  async function submit(e: Event) {
    e.preventDefault()
    if (busy) return
    notice = null
    if (!username) return void (msg = { text: ENTER_ACCOUNT })
    if (!password) return void (msg = { text: ENTER_PASSWORD })
    busy = true
    msg = null
    try {
      const reply = readLoginReply(await sendJSON('POST', '/api/auth/login', { username, password }))
      if (reply.kind === 'account') await onaccount(password)
      else if (reply.kind === 'secondFactor') onsecondfactor(reply.methods, password)
      // A confirmation code (#189) is not built yet.
      else msg = { text: FAILED }
    } catch (err) {
      if (statusOf(err) === 401 && kindOf(err) === 'invalid-credentials') {
        // The same words whether or not the account exists.
        msg = { text: 'Incorrect account or password.' }
        password = ''
        await tick()
        passwordEl?.focus()
      } else if (statusOf(err) === 429) msg = tooMany(ssoAvailable)
      else msg = { text: FAILED }
    } finally {
      busy = false
    }
  }
</script>

<form class="f-signin" novalidate onsubmit={submit}>
  <!-- Above the form: an SSO refusal, or a code step that timed out. -->
  <Alert msg={notice} />
  <label
    ><span class="sr-only">Account</span><input
      bind:this={accountEl}
      bind:value={username}
      placeholder="account"
      autocomplete="username"
    /></label
  >
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
  <button class="submit" disabled={busy}>{busy ? 'Please wait…' : 'Enter'}</button>
  {#if ssoAvailable}
    <div class="divider"><span>or</span></div>
    <a class="sso" href="/api/auth/oidc/login">Sign in with SSO</a>
  {/if}
</form>
