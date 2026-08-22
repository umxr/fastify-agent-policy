import type { FastifyRequest } from 'fastify'

import type { AgentIdentity, SyncAgentIdentityResolver } from '../types.js'

/** Maps already-verified token claims onto an agent identity. */
export type BearerClaimsMapper<Claims> = (
  claims: Claims,
  request: FastifyRequest,
) => AgentIdentity | null

/** Options for {@link bearerClaims}. */
export interface BearerClaimsResolverOptions {
  /**
   * Request property holding the verified claims. Defaults to `user`, which
   * is where `@fastify/jwt` puts them after `jwtVerify()`.
   */
  claimsProperty?: string
}

/**
 * Builds an identity from token claims another plugin has already verified.
 *
 * This plugin never parses or verifies a bearer token itself. Decoding a JWT
 * payload without checking its signature would turn an attacker-supplied
 * string into a policy identity. Verify first -- with `@fastify/jwt`,
 * `@fastify/oauth2` or your own hook -- then map the result here.
 *
 * Returns `null` when no claims are present, which is how a human request
 * with no token stays unpoliced under `applyTo: 'agents'`.
 */
export function bearerClaims<Claims = Record<string, unknown>>(
  mapFn: BearerClaimsMapper<Claims>,
  options: BearerClaimsResolverOptions = {},
): SyncAgentIdentityResolver {
  if (typeof mapFn !== 'function') {
    throw new TypeError('bearerClaims(mapFn) requires a mapping function')
  }
  const claimsProperty = options.claimsProperty ?? 'user'

  return function resolveBearerClaims(request: FastifyRequest): AgentIdentity | null {
    const claims = (request as unknown as Record<string, unknown>)[claimsProperty]
    if (claims === null || claims === undefined) return null
    return mapFn(claims as Claims, request) ?? null
  }
}
