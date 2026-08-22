import type { FastifyRequest } from 'fastify'

import type { AgentIdentity, SyncAgentIdentityResolver } from '../types.js'

/**
 * The subset of `fastify-web-bot-auth`'s request decoration this resolver
 * reads.
 *
 * Declared structurally rather than imported. That package is an optional
 * peer pinned to `0.1.x` and its shape is still unstable, so a type import
 * would leak into the published `.d.ts` and break consumers who do not
 * install it.
 */
export interface WebBotAuthResult {
  /** True only when the HTTP message signature verified against a live key. */
  verified: boolean
  /**
   * Whether the verified key belongs to a directory the host trusts.
   * `undefined` whenever `verified` is `false` -- never read it as
   * "falsy means denied".
   */
  trusted?: boolean
  /** The signature agent URL the caller signed with. */
  agent?: string
  /** The key id from the signature input. */
  keyid?: string
  [member: string]: unknown
}

interface RequestWithWebBotAuth {
  webBotAuth?: WebBotAuthResult | null
}

/** Options for {@link webBotAuth}. */
export interface WebBotAuthResolverOptions {
  /**
   * Where `fastify-web-bot-auth` puts its result. Defaults to `webBotAuth`.
   */
  property?: string
  /** Scopes to attach to every identity this resolver produces. */
  scopes?: string[]
}

/**
 * Normalizes a signature agent URL to its https origin.
 *
 * Returns `null` for anything that is not an https URL, so a `http://` or
 * `data:` value can never become an identity.
 */
export function normalizeAgentOrigin(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0) return null
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return null
  }
  if (url.protocol !== 'https:') return null
  return url.origin
}

/**
 * Consumes the decoration `fastify-web-bot-auth` leaves on the request.
 *
 * This resolver never dereferences the signature agent URL, fetches a key
 * directory or verifies a signature -- that is `fastify-web-bot-auth`'s job.
 * It only reads the verdict.
 *
 * - `verified !== true` produces `null`. There is no identity without proof.
 * - `trusted === true` produces `class: 'trusted'`, anything else
 *   `class: 'verified'`.
 * - `id` is the normalized https origin of the signature agent.
 */
export function webBotAuth(options: WebBotAuthResolverOptions = {}): SyncAgentIdentityResolver {
  const property = options.property ?? 'webBotAuth'
  const scopes = options.scopes

  return function resolveWebBotAuth(request: FastifyRequest): AgentIdentity | null {
    const result = (request as FastifyRequest & RequestWithWebBotAuth)[
      property as 'webBotAuth'
    ] as WebBotAuthResult | null | undefined

    if (result === null || result === undefined) return null
    if (result.verified !== true) return null

    const id = normalizeAgentOrigin(result.agent)
    if (id === null) return null

    // Undefined members are dropped rather than serialized as `keyid: null`.
    const meta: Record<string, unknown> = { signatureAgent: result.agent }
    if (result.keyid !== undefined) meta['keyid'] = result.keyid

    const identity: AgentIdentity = {
      id,
      class: result.trusted === true ? 'trusted' : 'verified',
      meta,
    }
    // Copied, never shared. One handler mutating `request.agent.scopes` would
    // otherwise rewrite the resolver's own array for every later request.
    if (scopes !== undefined) identity.scopes = [...scopes]
    return identity
  }
}
