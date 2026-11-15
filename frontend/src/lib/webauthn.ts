// The browser half of a passkey ceremony (issue #8): gauntlet's begin
// routes answer the W3C options JSON (`{publicKey: ...}`, binary fields
// base64url), and its finish routes take the W3C PublicKeyCredential JSON.
// Where the browser has the standard JSON helpers
// (PublicKeyCredential.parseCreationOptionsFromJSON / .toJSON(), as
// mikroview's lib/passkeys uses) they do the encoding; otherwise the
// same fields are converted here, so an older browser still works.

type Json = Record<string, unknown>

function fromB64url(s: string): ArrayBuffer {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out.buffer
}

function toB64url(buf: ArrayBuffer | ArrayBufferView | null | undefined): string | undefined {
  if (!buf) return undefined
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const decodeIds = (list: unknown) =>
  Array.isArray(list) ? list.map((c: Json) => ({ ...c, id: typeof c.id === 'string' ? fromB64url(c.id) : c.id })) : list

interface PKCStatic {
  parseRequestOptionsFromJSON?: (o: unknown) => PublicKeyCredentialRequestOptions
  parseCreationOptionsFromJSON?: (o: unknown) => PublicKeyCredentialCreationOptions
}
const pkc = (): PKCStatic | undefined => (typeof PublicKeyCredential === 'undefined' ? undefined : (PublicKeyCredential as unknown as PKCStatic))

function requestOptions(o: Json): PublicKeyCredentialRequestOptions {
  const parse = pkc()?.parseRequestOptionsFromJSON
  if (parse) return parse(o)
  return {
    ...o,
    challenge: fromB64url(String(o.challenge ?? '')),
    allowCredentials: decodeIds(o.allowCredentials),
  } as unknown as PublicKeyCredentialRequestOptions
}

function creationOptions(o: Json): PublicKeyCredentialCreationOptions {
  const parse = pkc()?.parseCreationOptionsFromJSON
  if (parse) return parse(o)
  const user = (o.user ?? {}) as Json
  return {
    ...o,
    challenge: fromB64url(String(o.challenge ?? '')),
    user: { ...user, id: fromB64url(String(user.id ?? '')) },
    excludeCredentials: decodeIds(o.excludeCredentials),
  } as unknown as PublicKeyCredentialCreationOptions
}

function credentialJSON(cred: Credential): Json {
  const c = cred as unknown as Json & { toJSON?: () => Json }
  if (typeof c.toJSON === 'function') return c.toJSON()
  const r = (c.response ?? {}) as Json & { getTransports?: () => string[] }
  const response: Json = {}
  for (const k of ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle', 'attestationObject']) {
    const v = toB64url(r[k] as ArrayBuffer | null | undefined)
    if (v !== undefined) response[k] = v
  }
  if (typeof r.getTransports === 'function') response.transports = r.getTransports()
  const ext = c.getClientExtensionResults as (() => Json) | undefined
  return {
    id: c.id,
    rawId: toB64url(c.rawId as ArrayBuffer) ?? c.id,
    type: c.type,
    response,
    clientExtensionResults: typeof ext === 'function' ? ext.call(c) : {},
    authenticatorAttachment: c.authenticatorAttachment ?? undefined,
  }
}

/** Thrown when the browser's prompt did not produce a credential
 * (cancelled, timed out, no usable passkey, or no WebAuthn here). */
export class CeremonyError extends Error {
  constructor() {
    super('passkey prompt did not complete')
    this.name = 'CeremonyError'
  }
}

async function run<T extends Credential | null>(p: () => Promise<T> | undefined): Promise<Json> {
  let cred: Credential | null | undefined
  try {
    cred = await p()
  } catch {
    throw new CeremonyError()
  }
  if (!cred) throw new CeremonyError()
  return credentialJSON(cred)
}

/** navigator.credentials.get() for a begin route's answer; the assertion JSON. */
export function getAssertion(begin: unknown): Promise<Json> {
  const o = ((begin as Json)?.publicKey ?? {}) as Json
  return run(() => navigator.credentials?.get({ publicKey: requestOptions(o) }))
}

/** navigator.credentials.create() for register/begin's answer; the credential JSON. */
export function createCredential(begin: unknown): Promise<Json> {
  const o = ((begin as Json)?.publicKey ?? {}) as Json
  return run(() => navigator.credentials?.create({ publicKey: creationOptions(o) }))
}
