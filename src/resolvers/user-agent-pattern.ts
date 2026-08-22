import type { FastifyRequest } from 'fastify'

import type { AgentIdentity, SyncAgentIdentityResolver } from '../types.js'

/** Options for {@link userAgentPattern}. */
export interface UserAgentPatternResolverOptions {
  /** Trust class to stamp on matches. Defaults to `unverified`. */
  class?: string
  /** Scopes to attach to every match. */
  scopes?: string[]
}

/**
 * Drops the `g` and `y` flags. A shared global regex carries `lastIndex`
 * between calls, so the same request would match on one call and miss on the
 * next.
 */
function withoutStatefulFlags(pattern: RegExp): RegExp {
  const flags = pattern.flags.replace(/[gy]/g, '')
  return flags === pattern.flags ? pattern : new RegExp(pattern.source, flags)
}

/**
 * Matches the `User-Agent` header against a list of patterns.
 *
 * A User-Agent string proves nothing -- anyone can send one -- so matches are
 * always `class: 'unverified'`. Use it for well-behaved crawlers and for
 * telemetry, not as the only gate on a destructive route.
 *
 * The identity `id` is the first capture group when the pattern has one, and
 * the whole matched text otherwise.
 */
export function userAgentPattern(
  patterns: RegExp[],
  options: UserAgentPatternResolverOptions = {},
): SyncAgentIdentityResolver {
  if (!Array.isArray(patterns) || patterns.length === 0) {
    throw new TypeError('userAgentPattern(patterns) requires a non-empty array of RegExp')
  }
  for (const pattern of patterns) {
    if (!(pattern instanceof RegExp)) {
      throw new TypeError('userAgentPattern(patterns) requires a non-empty array of RegExp')
    }
  }

  const safePatterns = patterns.map(withoutStatefulFlags)
  const identityClass = options.class ?? 'unverified'
  const scopes = options.scopes

  return function resolveUserAgentPattern(request: FastifyRequest): AgentIdentity | null {
    const header = request.headers['user-agent']
    if (typeof header !== 'string' || header.length === 0) return null

    for (const pattern of safePatterns) {
      const match = pattern.exec(header)
      if (match === null) continue

      const id = match[1] ?? match[0]
      if (id === undefined || id.length === 0) continue

      const identity: AgentIdentity = {
        id,
        class: identityClass,
        meta: { userAgent: header, pattern: pattern.source },
      }
      // Copied, never shared: a handler that mutates `request.agent.scopes`
      // must not rewrite the resolver's array for every later request.
      if (scopes !== undefined) identity.scopes = [...scopes]
      return identity
    }
    return null
  }
}
