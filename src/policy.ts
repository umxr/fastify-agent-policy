import createError from '@fastify/error'

import type {
  AgentPolicy,
  AgentPolicyDefaults,
  ConfirmMode,
  DryRunMode,
  MaxRiskAllowance,
  ResolvedAgentPolicy,
  RiskTier,
  ScopeRequirement,
} from './types.js'

/** Thrown from `onRoute` when a route declares a malformed `config.agent`. */
export const InvalidAgentPolicyError = createError<[string, string]>(
  'FST_AGENT_POLICY_INVALID_POLICY',
  'Invalid agent policy on route %s: %s',
  500,
)

/**
 * Where a policy object came from, and how to report a problem with it.
 *
 * The plugin `defaults` block and a route's `config.agent` share one
 * validator but are two different mistakes for the user to fix, so each
 * carries its own error constructor rather than the caller re-reading a
 * formatted message.
 */
interface PolicySource {
  /** Names the offending policy in the error message. */
  subject: string
  /** Builds the error for a shape problem found in this policy. */
  toError: (detail: string) => Error
}

/** Thrown from `onRoute` when no `risk` is declared and no default supplies one. */
export const MissingRiskTierError = createError<[string]>(
  'FST_AGENT_POLICY_RISK_REQUIRED',
  'Invalid agent policy on route %s: "risk" is required and plugin option "defaults.risk" is not set',
  500,
)

/** Thrown at plugin registration when the plugin options are malformed. */
export const InvalidAgentPolicyOptionsError = createError<[string]>(
  'FST_AGENT_POLICY_INVALID_OPTIONS',
  'Invalid fastify-agent-policy options: %s',
  500,
)

/**
 * Thrown from `onReady` when routes were registered before the plugin. Their
 * `onRoute` never fired, so their `config.agent` was never validated and can
 * never be enforced -- they look policed and are not.
 */
export const RoutesBeforePluginError = createError<[string]>(
  'FST_AGENT_POLICY_ROUTES_BEFORE_PLUGIN',
  'fastify-agent-policy was registered after these routes, so their agent policy was never validated and can never be enforced. Register the plugin before any route:\n%s',
  500,
)

/** Thrown when the plugin is registered twice on the same Fastify instance. */
export const DuplicateRegistrationError = createError(
  'FST_AGENT_POLICY_DUPLICATE_REGISTRATION',
  'fastify-agent-policy is already registered on this instance. A second registration would run identify() twice per request and silently discard its own options. Register it once, or in a separate encapsulated scope.',
  500,
)

/**
 * Thrown when the plugin is registered inside a scope that already has it
 * from an ancestor.
 *
 * `fastify-plugin` skips encapsulation, so a nested registration's hooks are
 * added to the same instance the ancestor's were: `identify()` and the whole
 * check chain run twice per request, and a side-effecting guard -- the
 * documented example is a spend counter -- charges twice. The nested
 * registration's own `defaults` are ignored on top of that, because the
 * ancestor's `onRoute` reaches each route first.
 */
export const NestedRegistrationError = createError(
  'FST_AGENT_POLICY_NESTED_REGISTRATION',
  'fastify-agent-policy is already registered on an enclosing Fastify instance. A nested registration would run identify() and every policy check twice per request -- double-charging any guard with a side effect -- and its own "defaults" would be silently ignored. Register it once at the level that owns the routes, or use sibling encapsulated scopes.',
  500,
)

/** Thrown at request time when a resolver returns something that is not an identity. */
export const InvalidAgentIdentityError = createError<[string]>(
  'FST_AGENT_POLICY_INVALID_IDENTITY',
  'The identify() resolver returned an invalid agent identity: %s',
  500,
)

/** The only keys a route policy may carry. */
export const POLICY_KEYS: readonly string[] = Object.freeze([
  'risk',
  'dryRun',
  'confirm',
  'scopes',
  'guard',
])

/**
 * Every risk tier, **in ascending order of damage**.
 *
 * The order is load-bearing, not cosmetic: `enforce.ts` derives the tier
 * comparison from these positions, so reordering this array silently changes
 * which routes an allowance permits. Append-only.
 */
export const RISK_TIERS: readonly RiskTier[] = Object.freeze(['read', 'write', 'destructive'])
const DRY_RUN_MODES: readonly DryRunMode[] = Object.freeze([false, 'preview', 'handler'])
const CONFIRM_MODES: readonly ConfirmMode[] = Object.freeze([false, 'two-phase'])

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function quoteList(values: readonly unknown[]): string {
  return values.map((value) => JSON.stringify(value)).join(', ')
}

function fail(source: PolicySource, detail: string): never {
  throw source.toError(detail)
}

function routeSource(routeName: string): PolicySource {
  return {
    subject: 'config.agent',
    toError: (detail) => new InvalidAgentPolicyError(routeName, detail),
  }
}

const DEFAULTS_SOURCE: PolicySource = {
  subject: 'the "defaults" option',
  toError: (detail) => new InvalidAgentPolicyOptionsError(`"defaults" -- ${detail}`),
}

function validateScopeList(source: PolicySource, property: string, value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    fail(source, `"${property}" must be a non-empty array of strings`)
  }
  for (const entry of value) {
    if (typeof entry !== 'string' || entry.length === 0) {
      fail(source, `"${property}" must contain only non-empty strings`)
    }
  }
  return value as string[]
}

function validateScopes(source: PolicySource, value: unknown): ScopeRequirement {
  if (Array.isArray(value)) {
    return validateScopeList(source, 'scopes', value)
  }
  if (!isPlainObject(value)) {
    fail(source, '"scopes" must be an array of strings, { any: [...] } or { all: [...] }')
  }
  const keys = Object.keys(value)
  if (keys.length !== 1 || (keys[0] !== 'any' && keys[0] !== 'all')) {
    fail(source, '"scopes" object form must have exactly one key, "any" or "all"')
  }
  const key = keys[0] as 'any' | 'all'
  const list = validateScopeList(source, `scopes.${key}`, value[key])
  return key === 'any' ? { any: list } : { all: list }
}

/**
 * Validates one policy object and returns a shallow copy. Does not merge
 * defaults and does not resolve `risk`; {@link validatePolicy} does that.
 */
function validatePolicyShape(source: PolicySource, policy: unknown): AgentPolicy {
  if (!isPlainObject(policy)) {
    fail(source, `${source.subject} must be an object`)
  }

  for (const key of Object.keys(policy)) {
    if (!POLICY_KEYS.includes(key)) {
      fail(source, `unknown property "${key}" (expected one of ${quoteList(POLICY_KEYS)})`)
    }
  }

  const validated: AgentPolicy = {}

  if (policy['risk'] !== undefined) {
    if (!RISK_TIERS.includes(policy['risk'] as RiskTier)) {
      fail(source, `"risk" must be one of ${quoteList(RISK_TIERS)}`)
    }
    validated.risk = policy['risk'] as RiskTier
  }

  if (policy['dryRun'] !== undefined) {
    if (!DRY_RUN_MODES.includes(policy['dryRun'] as DryRunMode)) {
      fail(source, `"dryRun" must be one of ${quoteList(DRY_RUN_MODES)}`)
    }
    validated.dryRun = policy['dryRun'] as DryRunMode
  }

  if (policy['confirm'] !== undefined) {
    if (!CONFIRM_MODES.includes(policy['confirm'] as ConfirmMode)) {
      fail(source, `"confirm" must be one of ${quoteList(CONFIRM_MODES)}`)
    }
    validated.confirm = policy['confirm'] as ConfirmMode
  }

  if (policy['scopes'] !== undefined) {
    validated.scopes = validateScopes(source, policy['scopes'])
  }

  if (policy['guard'] !== undefined) {
    if (typeof policy['guard'] !== 'function') {
      fail(source, '"guard" must be a function')
    }
    validated.guard = policy['guard'] as AgentPolicy['guard']
  }

  return validated
}

/**
 * Validates the plugin-level `defaults` block.
 *
 * Failures are reported as options errors from the start. Catching a route
 * error and re-reading its formatted message would also swallow unrelated
 * throws, and would say `config.agent` when the user set a plugin option.
 */
export function validateDefaults(defaults: unknown): AgentPolicyDefaults {
  if (defaults === undefined) return {}
  return validatePolicyShape(DEFAULTS_SOURCE, defaults)
}

/**
 * Validates the plugin-level `maxRisk` map and returns a null-prototype copy.
 *
 * The copy matters at request time: a lookup on a plain object literal for an
 * agent class named `constructor` or `toString` would find `Object.prototype`
 * and read a function as a risk tier. With no prototype there is nothing to
 * find, so an unlisted class always falls through to `default`.
 */
export function validateMaxRisk(maxRisk: unknown): MaxRiskAllowance | undefined {
  if (maxRisk === undefined) return undefined
  if (!isPlainObject(maxRisk)) {
    throw new InvalidAgentPolicyOptionsError(
      `"maxRisk" must be an object mapping an agent class to a risk tier (one of ${quoteList(RISK_TIERS)})`,
    )
  }

  // `{}` matches no class and has no `default`, so every agent on every
  // policed route is denied. It reads as "no restrictions configured" and
  // behaves as "deny all"; neither reading should be reachable by accident.
  if (Object.keys(maxRisk).length === 0) {
    throw new InvalidAgentPolicyOptionsError(
      '"maxRisk" must name at least one agent class. An empty map denies every agent on every policed route -- omit the option entirely to disable the risk tier check.',
    )
  }

  const allowance = Object.create(null) as Record<string, RiskTier>
  for (const [agentClass, tier] of Object.entries(maxRisk)) {
    if (agentClass.length === 0) {
      throw new InvalidAgentPolicyOptionsError('"maxRisk" keys must be non-empty agent class names')
    }
    if (!RISK_TIERS.includes(tier as RiskTier)) {
      throw new InvalidAgentPolicyOptionsError(
        `"maxRisk.${agentClass}" must be one of ${quoteList(RISK_TIERS)}`,
      )
    }
    allowance[agentClass] = tier as RiskTier
  }

  return Object.freeze(allowance)
}

/**
 * Validates `config.agent` for one route, merges the plugin `defaults`
 * underneath it and resolves `risk`.
 *
 * Throws a coded error naming the route and the offending property. Called
 * from the synchronous `onRoute` hook, so the throw surfaces as an
 * `app.ready()` rejection.
 */
export function validatePolicy(
  routeName: string,
  policy: unknown,
  defaults: AgentPolicyDefaults = {},
): ResolvedAgentPolicy {
  const declared = validatePolicyShape(routeSource(routeName), policy)
  const merged: AgentPolicy = { ...defaults, ...declared }

  // Never inferred from the HTTP method: a POST can be a read, and a GET can
  // be destructive.
  if (merged.risk === undefined) {
    throw new MissingRiskTierError(routeName)
  }

  return merged as ResolvedAgentPolicy
}

/** Formats `routeOptions.method` for an error message. */
export function formatRouteName(method: string | string[], url: string): string {
  const methods = Array.isArray(method) ? method.join(',') : method
  return `${methods} ${url}`
}
