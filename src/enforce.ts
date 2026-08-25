import type { FastifyRequest } from 'fastify'

import { RISK_TIERS } from './policy.js'
import type { ProblemExtensions, ProblemKind } from './problems.js'
import type {
  AgentGuard,
  AgentIdentity,
  MaxRiskAllowance,
  ResolvedAgentPolicy,
  RiskTier,
  ScopeRequirement,
} from './types.js'

/**
 * Each tier's position in `RISK_TIERS`, which is declared in ascending order
 * of damage. A route is allowed when its tier sits at or below the allowance
 * for the caller's class.
 *
 * Derived rather than restated: two hand-written orderings would be two
 * things to keep in step, and the one that drifted would silently widen an
 * allowance.
 */
const RISK_ORDER: Readonly<Record<RiskTier, number>> = Object.freeze(
  Object.fromEntries(RISK_TIERS.map((tier, index) => [tier, index])),
) as Readonly<Record<RiskTier, number>>

/** The `maxRisk` key used for any class the map does not list. */
export const DEFAULT_RISK_CLASS = 'default'

/**
 * A route's `scopes` reduced to one shape.
 *
 * `validatePolicy` returns the user's union unchanged -- it is the published
 * return type. Branching on that union per request would re-derive the same
 * answer on every call, so the reduction happens once, in `onRoute`.
 */
export interface ScopeCheck {
  /** `'all'` for a bare array and `{ all }`; `'any'` for `{ any }`. */
  readonly mode: 'any' | 'all'
  /** The scopes themselves. Also what `requiredScopes` reports. */
  readonly scopes: readonly string[]
}

/**
 * One refusal, ready for the log and the response.
 *
 * `reason` is log-only. It may name the guard's own words or the tier that
 * was exceeded; `detail` is what the caller is allowed to read.
 */
export interface Denial {
  /** The frozen problem type. Decides the status and the title. */
  kind: ProblemKind
  /** Why the request was refused. Logged, never sent. */
  reason: string
  /** The `detail` member of the problem document. Sent. */
  detail: string
  /** Whether repeating the same request unchanged can ever succeed. */
  retryable: boolean
  /** Extra problem members, e.g. `requiredScopes`. */
  extensions?: ProblemExtensions
}

/**
 * Reduces a route's declared `scopes` to a {@link ScopeCheck}, or `null` when
 * the route declares none. Call once per route, at registration.
 */
export function normalizeScopeRequirement(scopes: ScopeRequirement | undefined): ScopeCheck | null {
  if (scopes === undefined) return null

  if (Array.isArray(scopes)) {
    // A bare array is all-of. The object form exists to say so out loud.
    return Object.freeze({ mode: 'all', scopes: Object.freeze([...scopes]) })
  }
  if ('any' in scopes) {
    return Object.freeze({ mode: 'any', scopes: Object.freeze([...scopes.any]) })
  }
  return Object.freeze({ mode: 'all', scopes: Object.freeze([...scopes.all]) })
}

/**
 * The tier this agent's class may call, or `undefined` when nothing allows it.
 *
 * `maxRisk` is built with a null prototype at registration, so a class named
 * `constructor` or `toString` cannot borrow an allowance from `Object`.
 */
function allowanceFor(agent: AgentIdentity, maxRisk: MaxRiskAllowance): RiskTier | undefined {
  const declared = typeof agent.class === 'string' ? maxRisk[agent.class] : undefined
  if (declared !== undefined) return declared
  return maxRisk[DEFAULT_RISK_CLASS]
}

/**
 * Whether the agent's class may call a route of this tier.
 *
 * An unset `maxRisk` disables the check entirely. A class the map does not
 * list falls back to `default`; with no `default` either, the answer is no --
 * an unrecognized class is exactly when guessing is most expensive.
 */
export function checkRisk(
  agent: AgentIdentity,
  risk: RiskTier,
  maxRisk: MaxRiskAllowance | undefined,
): Denial | null {
  if (maxRisk === undefined) return null

  const allowance = allowanceFor(agent, maxRisk)
  if (allowance === undefined) {
    return {
      kind: 'risk_tier_blocked',
      reason: `agent class ${JSON.stringify(agent.class ?? null)} has no maxRisk allowance and no "default" is configured`,
      // The configured map is deployment detail. Naming the tier the caller
      // failed to clear would let an agent enumerate the allowance table.
      detail: 'This agent is not allowed to call this route.',
      retryable: false,
    }
  }

  if (RISK_ORDER[risk] <= RISK_ORDER[allowance]) return null

  return {
    kind: 'risk_tier_blocked',
    reason: `route risk "${risk}" exceeds the "${allowance}" allowance for agent class ${JSON.stringify(agent.class ?? null)}`,
    detail: 'This route is above the risk tier this agent is allowed to call.',
    retryable: false,
  }
}

/**
 * Whether the agent holds the scopes the route requires.
 *
 * Scopes match by exact string equality. There is no wildcard, no hierarchy
 * and no prefix rule: `orders:*` is a scope literally named `orders:*`.
 */
export function checkScopes(agent: AgentIdentity, required: ScopeCheck | null): Denial | null {
  if (required === null) return null

  const held = Array.isArray(agent.scopes) ? new Set(agent.scopes) : new Set<string>()
  const satisfied =
    required.mode === 'any'
      ? required.scopes.some((scope) => held.has(scope))
      : required.scopes.every((scope) => held.has(scope))

  if (satisfied) return null

  return {
    kind: 'scope_denied',
    reason:
      required.mode === 'any'
        ? `agent holds none of the required scopes (any of: ${required.scopes.join(', ')})`
        : `agent does not hold every required scope (all of: ${required.scopes.join(', ')})`,
    detail:
      required.mode === 'any'
        ? 'This route requires at least one of the scopes listed in requiredScopes.'
        : 'This route requires every scope listed in requiredScopes.',
    retryable: false,
    // Already a declared member of `ProblemExtensions`; the route asked for
    // these scopes in its own config, so echoing them leaks nothing.
    extensions: { requiredScopes: [...required.scopes] },
  }
}

/**
 * The longest guard `reason` that may become a problem `detail`.
 *
 * A guard is userland code and its reason is published to the caller. An
 * unbounded string would let an accidental `JSON.stringify(everything)` become
 * the response body.
 */
export const MAX_GUARD_REASON_LENGTH = 200

/**
 * Trims a guard's reason to something safe to publish.
 *
 * Control characters are stripped -- they have no meaning in a problem
 * `detail` and are how a log-forging or terminal-escape payload travels --
 * runs of whitespace collapse to one space so the removal leaves no gap, and
 * the result is capped. Returns `undefined` when nothing usable is left, so
 * the caller falls back to the generic wording.
 */
function sanitizeReason(reason: string): string | undefined {
  const stripped = reason
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (stripped.length === 0) return undefined
  if (stripped.length <= MAX_GUARD_REASON_LENGTH) return stripped
  return `${stripped.slice(0, MAX_GUARD_REASON_LENGTH - 1).trimEnd()}\u2026`
}

/** A guard result that is neither `true` nor `{ allow: true }` denies. */
function guardDenial(reason: string | undefined): Denial {
  return {
    kind: 'guard_failed',
    reason: reason ?? 'guard returned a denial',
    // The guard's own words. A guard is userland code that chose to explain
    // itself, so unlike a thrown message this is meant for the caller.
    detail: reason ?? 'The guard for this route refused the request.',
    retryable: false,
  }
}

/**
 * Runs the route's guard. The last check, and the only one that is not
 * declarative.
 *
 * This runs from `preHandler`, not `onRequest`, because a guard's whole job
 * is inspecting the request -- `request.body.amount <= 500` is the canonical
 * example -- and in `onRequest` the body has not been parsed yet, so every
 * such guard would read `undefined` and refuse a perfectly valid call. By
 * `preHandler` the body is parsed and schema-validated.
 *
 * A guard that throws is handled the way a failing `identify()` is: the error
 * goes to `request.log.error` and never to the caller, because a guard can
 * name an internal host or carry a token in its message. The denial is
 * `retryable: true` -- an exception is a failure to decide, not a decision.
 */
export async function checkGuard(
  request: FastifyRequest,
  agent: AgentIdentity,
  guard: AgentGuard | undefined,
): Promise<Denial | null> {
  if (guard === undefined) return null

  let result: unknown
  try {
    result = await guard(request, agent)
  } catch (error) {
    request.log.error({ err: error }, 'fastify-agent-policy: guard() failed')
    return {
      kind: 'guard_failed',
      reason: 'guard() failed',
      detail: 'The guard for this route could not be evaluated right now. Retry the request.',
      retryable: true,
    }
  }

  if (result === true) return null
  if (result === false) return guardDenial(undefined)

  if (typeof result === 'object' && result !== null && !Array.isArray(result)) {
    const answer = result as { allow?: unknown; reason?: unknown }
    // Strictly `true`. A truthy-but-not-true `allow` -- `'yes'`, `1`, a
    // stray object -- is a guard whose author did not mean what the type
    // says, and widening this to a truthiness test would grant on a typo.
    if (answer.allow === true) return null
    return guardDenial(typeof answer.reason === 'string' ? sanitizeReason(answer.reason) : undefined)
  }

  // Neither a boolean nor a `GuardResult` object. A guard that cannot say
  // "yes" does not get to mean "yes".
  request.log.warn(
    { agentPolicy: { guard: 'unsupported-result', received: typeof result } },
    'fastify-agent-policy: guard() returned a value that is not a GuardResult; treating it as a denial',
  )
  return guardDenial(undefined)
}

/**
 * The declarative half of enforcement: risk, then scopes. Returns the first
 * refusal, or `null` when both pass.
 *
 * This half runs in `onRequest`, the earliest hook there is, so a caller who
 * cannot clear it is turned away before the body is read at all. Both checks
 * answer from data already in hand, so the whole half is synchronous.
 *
 * The guard is the other half, and runs later -- see {@link checkGuard}. The
 * order across the two is risk, then scopes, then guard, and it is fixed: a
 * request failing several checks must always yield the same problem type, and
 * an agent that fixes its scopes must not then discover a tier ceiling it
 * could have been told about first.
 */
export function evaluateGate(
  agent: AgentIdentity,
  policy: ResolvedAgentPolicy,
  scopes: ScopeCheck | null,
  maxRisk: MaxRiskAllowance | undefined,
): Denial | null {
  return checkRisk(agent, policy.risk, maxRisk) ?? checkScopes(agent, scopes)
}
