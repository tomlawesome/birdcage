<script lang="ts">
  // Add a second step: choose a key, prove it works, keep the codes. Every
  // local-password account must hold one, so there is no skip, cancel or
  // sign-out here. gauntlet holds a first factor and its ten recovery
  // codes until "I have saved these" confirms them (its #58).
  //
  // The recovery codes live in this component's memory only: never in
  // storage, the address or the log, and gone when the screen goes.
  import { onMount, tick } from 'svelte'
  import { sendJSON } from '../lib/api'
  import type { SessionState } from '../lib/auth'
  import { CeremonyError, createCredential } from '../lib/webauthn'
  import Alert from './Alert.svelte'
  import { HAS_QR, drawQR } from './qr'
  import { ENTER_APP_CODE, ENTER_PASSWORD, FAILED, INCORRECT_CODE, INCORRECT_PASSWORD, kindOf, statusOf, TOO_MANY, type Message } from './messages'

  let {
    session,
    password: held = '',
    onpassword,
    ondone,
  }: {
    session: SessionState
    /** The password typed earlier in this visit, if the door holds one. */
    password?: string
    /** A password typed here, for the door to hold for this visit. */
    onpassword: (password: string) => void
    /** The factor is live (or the step must be read again): re-read the session. */
    ondone: () => void
  } = $props()

  type Key = 'totp' | 'passkey'
  type Stage = 'choose' | 'password' | 'prove-totp' | 'prove-passkey' | 'codes'
  let stage: Stage = $state('choose')
  let target: Key = $state('totp')

  const passkeyReady = $derived(session.passkeys?.status === 'ready')
  const totpOffered = $derived(!session.mustEnrolPasskey)

  let typed = $state('')
  let code = $state('')
  let name = $state('')
  let enrolment = $state<{ uri: string; secret: string } | null>(null)
  let codes: string[] = $state([])
  let copied = $state(false)
  let busy = $state(false)
  let prompting = $state(false)
  let msg: Message | null = $state(null)
  let fieldEl: HTMLInputElement | undefined = $state()
  let qrEl: HTMLCanvasElement | undefined = $state()

  const secretGroups = $derived((enrolment?.secret ?? '').replace(/\s+/g, '').match(/.{1,4}/g)?.join(' ') ?? '')

  $effect(() => {
    if (HAS_QR && qrEl && enrolment) drawQR(qrEl, enrolment.uri)
  })

  async function show(next: Stage) {
    stage = next
    await tick()
    fieldEl?.focus({ preventScroll: true })
  }
  onMount(() => fieldEl?.focus({ preventScroll: true }))

  /** Forget the held password and ask for it again. */
  function askPassword(for_: Key, why: Message | null) {
    held = ''
    typed = ''
    target = for_
    msg = why
    void show('password')
  }

  async function enrolTotp(pw: string) {
    const r = await sendJSON<{ uri: string; secret: string }>('POST', '/api/auth/totp/enrol', { password: pw })
    enrolment = { uri: r.uri, secret: r.secret }
    code = ''
  }

  function failed(err: unknown, key: Key) {
    if (statusOf(err) === 401 && kindOf(err) === 'invalid-credentials') askPassword(key, { text: INCORRECT_PASSWORD })
    else if (statusOf(err) === 429) msg = { text: TOO_MANY }
    else msg = { text: FAILED }
  }

  async function pick(key: Key) {
    if (busy) return
    msg = null
    if (!held) return askPassword(key, null)
    if (key === 'passkey') return void show('prove-passkey')
    busy = true
    try {
      await enrolTotp(held)
      await show('prove-totp')
    } catch (err) {
      failed(err, 'totp')
    } finally {
      busy = false
    }
  }

  async function submitPassword(e: Event) {
    e.preventDefault()
    if (busy) return
    if (!typed) return void (msg = { text: ENTER_PASSWORD })
    msg = null
    const pw = typed
    if (target === 'passkey') {
      held = pw
      onpassword(pw)
      return void show('prove-passkey')
    }
    busy = true
    try {
      await enrolTotp(pw)
      held = pw
      onpassword(pw)
      await show('prove-totp')
    } catch (err) {
      failed(err, 'totp')
    } finally {
      busy = false
    }
  }

  function gotCodes(list: string[] | null | undefined) {
    if (Array.isArray(list) && list.length) {
      codes = list
      msg = null
      void show('codes')
    } else ondone() // a later factor: live at once, no codes
  }

  async function confirmTotp(e: Event) {
    e.preventDefault()
    if (busy) return
    if (!code) return void (msg = { text: ENTER_APP_CODE })
    busy = true
    msg = null
    try {
      const r = await sendJSON<{ recoveryCodes: string[] | null }>('POST', '/api/auth/totp/confirm', { code })
      gotCodes(r.recoveryCodes)
    } catch (err) {
      if (statusOf(err) === 400) {
        msg = { text: INCORRECT_CODE }
        code = ''
      } else if (statusOf(err) === 401 && kindOf(err) === 'step-expired') {
        // The pending secret ran out: start the step again with a new one.
        try {
          await enrolTotp(held)
        } catch (again) {
          failed(again, 'totp')
        }
      } else failed(err, 'totp')
    } finally {
      busy = false
    }
  }

  async function addPasskey(e: Event) {
    e.preventDefault()
    if (busy) return
    busy = true
    msg = null
    try {
      const options = await sendJSON('POST', '/api/auth/passkeys/register/begin', { password: held })
      prompting = true
      const credential = await createCredential(options).finally(() => (prompting = false))
      const r = await sendJSON<{ recoveryCodes: string[] | null }>('POST', '/api/auth/passkeys/register/finish', { credential, name })
      gotCodes(r.recoveryCodes)
    } catch (err) {
      if (err instanceof CeremonyError) msg = { text: FAILED }
      else failed(err, 'passkey')
    } finally {
      busy = false
    }
  }

  async function copyAll() {
    try {
      await navigator.clipboard.writeText(codes.join('\n'))
      copied = true
    } catch {
      copied = false
    }
  }

  function download() {
    const url = URL.createObjectURL(new Blob([codes.join('\n') + '\n'], { type: 'text/plain' }))
    const a = document.createElement('a')
    a.href = url
    a.download = 'birdcage-recovery-codes.txt'
    a.click()
    URL.revokeObjectURL(url)
  }

  async function saved(e: Event) {
    e.preventDefault()
    if (busy) return
    busy = true
    msg = null
    try {
      await sendJSON('POST', '/api/auth/recovery-codes/confirm')
      codes = []
      ondone()
    } catch (err) {
      if (statusOf(err) === 401 && kindOf(err) === 'step-expired') {
        // The hold ran out and the factor went with it: set it up again.
        codes = []
        enrolment = null
        void show('choose')
      } else if (statusOf(err) === 409) ondone()
      else msg = { text: FAILED }
    } finally {
      busy = false
    }
  }
</script>

{#if stage === 'choose'}
  <form class="f-choose f-wide" novalidate onsubmit={(e) => e.preventDefault()}>
    <p class="thread"><b>choose</b> · prove it · keep the codes · enter</p>
    <h1>Add a second step</h1>
    <p class="subtitle">Every account needs one. Pick a key and prove it works.</p>
    {#if totpOffered}
      <button type="button" class="key" disabled={busy} onclick={() => pick('totp')}
        ><span class="g">428<br />116</span>Authenticator app<i>set it up ▸</i><small>A code from your phone.</small></button
      >
    {/if}
    <button type="button" class="key" disabled={!passkeyReady || busy} onclick={() => pick('passkey')}
      ><span class="g"
        ><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"
          ><path
            d="M12 11v4a8 8 0 0 0 1 4M8.5 20a12 12 0 0 1-1-5v-4a4.5 4.5 0 0 1 9 0v3a12 12 0 0 0 .8 4.3M4.5 16.5a16 16 0 0 1-.5-4V11a8 8 0 0 1 13-6.2M20 11v2.5"
          /></svg
        ></span
      >Passkey<i>set it up ▸</i><small>{passkeyReady ? 'Fingerprint, face or device PIN.' : 'Passkeys need an https web address.'}</small></button
    >
    <Alert {msg} />
  </form>
{:else if stage === 'password'}
  <form class="f-prove f-wide" novalidate onsubmit={submitPassword}>
    <p class="thread">choose · <b>prove it</b> · keep the codes · enter</p>
    <label
      ><span class="sr-only">Password</span><input
        bind:this={fieldEl}
        bind:value={typed}
        type="password"
        placeholder="password"
        autocomplete="current-password"
      /></label
    >
    <Alert {msg} />
    <button class="submit" disabled={busy}>{busy ? 'Please wait…' : 'Continue'}</button>
  </form>
{:else if stage === 'prove-totp'}
  <form class="f-prove f-wide" novalidate onsubmit={confirmTotp}>
    <p class="thread">choose · <b>prove it</b> · keep the codes · enter</p>
    <h1>Prove it works</h1>
    <p class="subtitle">Scan this with your authenticator app, then enter the code it shows.</p>
    {#if HAS_QR}<canvas class="qr" bind:this={qrEl} width="232" height="232" aria-label="QR code"></canvas>{/if}
    <span class="cap">Secret</span><span class="secret">{secretGroups}</span>
    <label
      ><span class="sr-only">Code from the app</span><input
        bind:this={fieldEl}
        bind:value={code}
        inputmode="numeric"
        maxlength="6"
        placeholder="6-digit code"
        autocomplete="one-time-code"
      /></label
    >
    <Alert {msg} />
    <button class="submit" disabled={busy}>{busy ? 'Please wait…' : 'Confirm'}</button>
    <p class="note">Confirming signs this account out everywhere else.</p>
    {#if passkeyReady}
      <button type="button" class="link" onclick={() => ((msg = null), show('prove-passkey'))}>Use a passkey instead</button>
    {/if}
  </form>
{:else if stage === 'prove-passkey'}
  <form class="f-prove f-wide" novalidate onsubmit={addPasskey}>
    <p class="thread">choose · <b>prove it</b> · keep the codes · enter</p>
    <h1>Prove it works</h1>
    <p class="subtitle">Name this passkey. Your browser asks for the fingerprint, face or PIN.</p>
    <label><span class="sr-only">Passkey name</span><input bind:this={fieldEl} bind:value={name} placeholder="name" autocomplete="off" /></label>
    <Alert {msg} />
    <button class="submit" disabled={busy}>{prompting ? 'Waiting…' : busy ? 'Please wait…' : 'Add passkey'}</button>
    {#if totpOffered}
      <button type="button" class="link" onclick={() => ((msg = null), pick('totp'))}>Use an authenticator app instead</button>
    {/if}
  </form>
{:else}
  <form class="f-codes f-wide" novalidate onsubmit={saved}>
    <p class="thread">choose · prove it · <b>keep the codes</b> · enter</p>
    <h1>Keep the codes</h1>
    <p class="subtitle">Ten recovery codes. Each works once in place of your second step. They are not shown again.</p>
    <div class="grid">
      {#each codes as c, i (i)}<span>{c}</span>{/each}
    </div>
    <div class="row">
      <button type="button" class="ghost" onclick={copyAll}>{copied ? 'Copied' : 'Copy all'}</button><button
        type="button"
        class="ghost"
        onclick={download}>Download</button
      >
    </div>
    <Alert {msg} />
    <button class="submit" disabled={busy}>{busy ? 'Please wait…' : 'I have saved these'}</button>
  </form>
{/if}
