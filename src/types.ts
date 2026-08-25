import type { FastifyRequest } from 'fastify'

/**
 * How damaging a route is when an agent calls it.
 *
 * The tier is always declared. The plugin never infers it from the HTTP
 * method: a `POST /reports/search` is a read, and a `GET /jobs/:id/cancel`
 * is not.
 */
export type RiskTier = 'read' | 'write' | 'destructive'

/**
 * The caller identity a resolver produces.
 *
 * `id` is the only required member. It must be stable for the same caller,
 * because later goals bind confirmation tokens to it.
 */
export interface AgentIdentity {
  /** Stable identifier for the caller, e.g. a normalized https origin. */
  id: string
  /** Scopes the caller presented. Matched by exact string equality. */
  scopes?: string[]
  /**
   * Trust class of the identity. The built-in resolvers emit
   * `'trusted' | 'verified' | 'unverified'`; userland resolvers may emit
   * any string.
   */
  class?: string
  /** Resolver-specific detail. Never interpreted by the plugin. */
  meta?: Record<string, unknown>
}

/** Resolves the calling agent, or `null` when the caller is not an agent. */
export type AgentIdentityResolver = (
  request: FastifyRequest,
) => AgentIdentity | null | Promise<AgentIdentity | null>

/**
 * A resolver that answers without awaiting anything. Every built-in resolver
 * is one, so callers can use its result directly.
 */
export type SyncAgentIdentityResolver = (request: FastifyRequest) => AgentIdentity | null

/**
 * Scopes a route requires.
 *
 * A bare array means every listed scope is required. Use the object form to
 * be explicit.
 */
export type ScopeRequirement = string[] | { any: string[] } | { all: string[] }

/** What a guard may answer. `false` and `{ allow: false }` both deny. */
export type GuardResult = boolean | { allow: boolean; reason?: string }

/** A userland predicate run against an identified agent. */
export type AgentGuard = (
  request: FastifyRequest,
  agent: AgentIdentity,
) => GuardResult | Promise<GuardResult>

/** How a route answers a dry-run request. */
export type DryRunMode = false | 'preview' | 'handler'

/** How a route demands confirmation before it runs. */
export type ConfirmMode = false | 'two-phase'

/**
 * The policy a route declares under `config.agent`.
 *
 * Every member except `risk` is optional, and `risk` may instead come from
 * the plugin-level `defaults`. Validation runs at route registration, so a
 * malformed policy fails `app.ready()` rather than a request.
 */
export interface AgentPolicy {
  /** Damage tier of this route. Required here or in plugin `defaults`. */
  risk?: RiskTier
  /** Dry-run support. Declared now; enforced by a later goal. */
  dryRun?: DryRunMode
  /** Two-phase confirmation. Declared now; enforced by a later goal. */
  confirm?: ConfirmMode
  /** Scopes the agent must hold. Matched by exact string equality. */
  scopes?: ScopeRequirement
  /** Custom predicate. Runs last, only for an identified agent. */
  guard?: AgentGuard
}

/** Plugin-level policy fallbacks, merged under every route policy. */
export type AgentPolicyDefaults = AgentPolicy

/**
 * A route policy after plugin `defaults` are merged in. `risk` is resolved,
 * so it is no longer optional.
 */
export interface ResolvedAgentPolicy extends AgentPolicy {
  risk: RiskTier
}

/**
 * The highest {@link RiskTier} each agent class may call.
 *
 * Keys are `AgentIdentity.class` values. Tiers compare in ascending order of
 * damage -- `read` < `write` < `destructive` -- and an allowance is inclusive.
 *
 * ```ts
 * maxRisk: { trusted: 'destructive', verified: 'write', default: 'read' }
 * ```
 *
 * `default` is **reserved**: it is the allowance for every class the map does
 * not list, so an agent class literally named `default` silently takes the
 * fallback and cannot be given an entry of its own. Rename the class if your
 * resolver can emit it.
 *
 * Without a `default`, an unlisted class is denied -- as is an identity
 * carrying no `class` at all. An empty map is rejected at registration: it
 * denies everything while reading as "nothing configured". Leave the option
 * unset to disable the tier check entirely.
 */
export type MaxRiskAllowance = Record<string, RiskTier>

/** Who the policy applies to. */
export type ApplyTo = 'agents' | 'all'

/**
 * What to do about routes registered before the plugin.
 *
 * `onRoute` only fires for routes registered after the plugin loads, so an
 * earlier route is never validated and can never be denied -- while still
 * getting `request.agent`. It looks policed and is not.
 *
 * - `'strict'` (default) fails the boot with a coded error naming the routes.
 * - `'warn'` logs a warning naming them and boots.
 * - `'off'` skips the check.
 *
 * Fastify exposes no way to read a route's `config` at boot, so the check
 * cannot tell a policed pre-plugin route from an unpoliced one. `'strict'`
 * therefore also rejects a plain `app.get('/health')` declared before the
 * plugin. `'warn'` and `'off'` reopen the silent-unpoliced-route hole.
 */
export type RegistrationOrder = 'strict' | 'warn' | 'off'

/** Options accepted by the plugin. */
export interface AgentPolicyOptions {
  /**
   * Resolves `request.agent`. Required -- there is no default identity
   * scheme, because guessing one is how you attach policy to a spoofable
   * header.
   */
  identify: AgentIdentityResolver
  /**
   * `'agents'` (default) leaves unidentified traffic alone. `'all'` denies
   * unidentified callers on policed routes with `agent_identity_required`.
   */
  applyTo?: ApplyTo
  /** Policy members every route inherits unless it overrides them. */
  defaults?: AgentPolicyDefaults
  /**
   * The highest risk tier each agent class may call, keyed by
   * `AgentIdentity.class` with a `default` fallback.
   *
   * Unset -- the default -- skips the tier check; scopes and guards still
   * run. Set it, and a class with no entry and no `default` is denied.
   */
  maxRisk?: MaxRiskAllowance
  /**
   * Base URI the RFC 9457 `type` slugs hang off. It identifies the problem
   * type; it does not have to be dereferenceable, but it must parse as a URI:
   * a value `new URL()` rejects fails at registration.
   */
  problemBaseUri?: string
  /**
   * The `WWW-Authenticate` challenge sent with a 401, which RFC 9110 makes
   * mandatory. Defaults to `Bearer realm="agent-policy"`. Set it to match
   * whatever your `identify` resolver actually reads.
   */
  wwwAuthenticate?: string
  /**
   * How to handle routes registered before the plugin. Defaults to
   * `'strict'`. See {@link RegistrationOrder} for the trade-off.
   */
  registrationOrder?: RegistrationOrder
}

declare module 'fastify' {
  interface FastifyRequest {
    /** The calling agent, or `null` when the caller is not an agent. */
    agent: AgentIdentity | null
  }

  interface FastifyContextConfig {
    /** The agent policy for this route. */
    agent?: AgentPolicy
  }
}
