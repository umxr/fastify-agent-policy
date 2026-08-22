import fp from 'fastify-plugin'
import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest, RouteOptions } from 'fastify'

import {
  DuplicateRegistrationError,
  InvalidAgentIdentityError,
  InvalidAgentPolicyOptionsError,
  RoutesBeforePluginError,
  formatRouteName,
  validateDefaults,
  validatePolicy,
} from './policy.js'
import {
  DEFAULT_PROBLEM_BASE_URI,
  DEFAULT_WWW_AUTHENTICATE,
  isValidProblemBaseUri,
  kAgentPolicyState,
  sendProblem,
  type AgentPolicyState,
} from './problems.js'
import type {
  AgentIdentity,
  AgentPolicyOptions,
  ApplyTo,
  RegistrationOrder,
  ResolvedAgentPolicy,
} from './types.js'

interface NormalizedOptions extends Required<Omit<AgentPolicyOptions, 'defaults'>> {
  defaults: AgentPolicyOptions['defaults']
}

/**
 * Where the validated policy is parked on the route's `config` object.
 *
 * A `WeakMap` keyed on `routeOptions.config` does not work: Fastify builds
 * the request-time config as a fresh `{ ...opts.config, url, method }` object
 * *after* the `onRoute` hooks run, so the registration-time object is never
 * seen again. Object spread does copy enumerable own symbols, so a symbol
 * property set here rides along -- and stays invisible to `Object.keys` and
 * `JSON.stringify`.
 */
const kResolvedPolicy = Symbol('fastify-agent-policy.resolvedPolicy')

/** A route `config` after `onRoute` has validated its policy. */
interface PolicedConfig {
  [kResolvedPolicy]?: ResolvedAgentPolicy
  agent?: unknown
}

/** What `printRoutes()` returns when the router is empty. */
const EMPTY_ROUTE_TREE = '(empty tree)'

const REGISTRATION_ORDERS: readonly RegistrationOrder[] = Object.freeze([
  'strict',
  'warn',
  'off',
])

/**
 * Apps whose route table has already been swept.
 *
 * The router is shared by every scope of an app, so `printRoutes()` from an
 * encapsulated instance still lists the whole application. That makes the
 * snapshot attributable only for the first registration in an app; a second
 * one -- a sibling scope -- would otherwise see its sibling's routes and
 * report them as unpoliced. Keyed on the HTTP server, the one public handle
 * every scope of an app shares.
 */
const sweptApps = new WeakSet<object>()

function normalizeOptions(options: AgentPolicyOptions): NormalizedOptions {
  if (options === null || typeof options !== 'object') {
    throw new InvalidAgentPolicyOptionsError('options must be an object')
  }
  if (typeof options.identify !== 'function') {
    throw new InvalidAgentPolicyOptionsError('"identify" is required and must be a function')
  }

  const applyTo = options.applyTo ?? 'agents'
  if (applyTo !== 'agents' && applyTo !== 'all') {
    throw new InvalidAgentPolicyOptionsError('"applyTo" must be "agents" or "all"')
  }

  // RFC 9457 requires `type` to be a URI reference. A base that `new URL()`
  // refuses would ship a malformed contract to every caller, so it fails here.
  const problemBaseUri = options.problemBaseUri ?? DEFAULT_PROBLEM_BASE_URI
  if (!isValidProblemBaseUri(problemBaseUri)) {
    throw new InvalidAgentPolicyOptionsError(
      `"problemBaseUri" must be a valid URI (received ${JSON.stringify(options.problemBaseUri)})`,
    )
  }

  const wwwAuthenticate = options.wwwAuthenticate ?? DEFAULT_WWW_AUTHENTICATE
  if (typeof wwwAuthenticate !== 'string' || wwwAuthenticate.length === 0) {
    throw new InvalidAgentPolicyOptionsError('"wwwAuthenticate" must be a non-empty string')
  }

  const registrationOrder = options.registrationOrder ?? 'strict'
  if (!REGISTRATION_ORDERS.includes(registrationOrder)) {
    throw new InvalidAgentPolicyOptionsError(
      '"registrationOrder" must be "strict", "warn" or "off"',
    )
  }

  return {
    identify: options.identify,
    applyTo: applyTo as ApplyTo,
    problemBaseUri,
    wwwAuthenticate,
    registrationOrder: registrationOrder as RegistrationOrder,
    defaults: validateDefaults(options.defaults),
  }
}

/**
 * The routes already in the router, or `null` when there are none.
 *
 * Anything here was registered before this plugin loaded, so `onRoute` never
 * saw it.
 */
function capturePreExistingRoutes(fastify: FastifyInstance): string | null {
  const tree = fastify.printRoutes({ commonPrefix: false }).trimEnd()
  if (tree.trim().length === 0) return null
  if (tree.trim() === EMPTY_ROUTE_TREE) return null
  return tree
}

function normalizeIdentity(value: unknown): AgentIdentity | null {
  if (value === null || value === undefined) return null
  if (typeof value !== 'object' || Array.isArray(value)) {
    throw new InvalidAgentIdentityError(`expected an object or null, got ${typeof value}`)
  }
  const identity = value as Partial<AgentIdentity>
  if (typeof identity.id !== 'string' || identity.id.length === 0) {
    throw new InvalidAgentIdentityError('"id" must be a non-empty string')
  }
  return identity as AgentIdentity
}

/**
 * Records the plugin's state on this instance, shadowing any ancestor's.
 *
 * `decorate()` is deliberately not used: it rejects a name that merely exists
 * on the prototype chain, which would make a nested registration impossible
 * and would silently hand `sendProblem` an ancestor's `problemBaseUri`. A
 * private symbol cannot collide with anything, and plain property lookup from
 * `reply.server` then finds the nearest enclosing registration.
 */
function attachState(fastify: FastifyInstance, state: AgentPolicyState): void {
  Object.defineProperty(fastify, kAgentPolicyState, {
    value: state,
    enumerable: false,
    configurable: true,
    writable: false,
  })
}

const agentPolicy: FastifyPluginAsync<AgentPolicyOptions> = async (fastify, opts) => {
  // `fastify-plugin` skips the encapsulation override, so this is the very
  // instance the caller registered against. An own property therefore means
  // a second registration at the same level; an inherited one means an
  // enclosing scope registered it, which is a legitimate nesting.
  if (Object.prototype.hasOwnProperty.call(fastify, kAgentPolicyState)) {
    throw new DuplicateRegistrationError()
  }

  const options = normalizeOptions(opts)

  attachState(fastify, {
    problemBaseUri: options.problemBaseUri,
    wwwAuthenticate: options.wwwAuthenticate,
  })

  // Routes already in the router were registered before this plugin loaded,
  // so `onRoute` never saw them. Captured now, reported from `onReady`, and
  // only for the first registration in this app -- see `sweptApps`.
  const app: object = fastify.server ?? fastify
  const isFirstRegistration = !sweptApps.has(app)
  sweptApps.add(app)
  const routesBeforePlugin =
    isFirstRegistration && options.registrationOrder !== 'off'
      ? capturePreExistingRoutes(fastify)
      : null

  // Set to null once, then assigned per request inside the hook. Fastify v5
  // refuses reference values here, and sharing one object across requests
  // would leak identities between callers.
  if (!fastify.hasRequestDecorator('agent')) {
    fastify.decorateRequest('agent', null)
  }

  fastify.addHook('onRoute', (routeOptions: RouteOptions) => {
    const config = routeOptions.config as PolicedConfig | undefined
    if (config === undefined || config === null) return

    // Only `agent` is policy. Fastify's own `url` and `method` keys, and any
    // other key the host app parks on `config`, are left alone.
    const declared = config.agent
    if (declared === undefined) return

    // `onRoute` fires twice for a GET: Fastify adds the HEAD route from a
    // shallow copy of the same options, so both invocations share one
    // `config` object. Validate the first, skip the second.
    if (config[kResolvedPolicy] !== undefined) return

    const routeName = formatRouteName(routeOptions.method, routeOptions.url)
    config[kResolvedPolicy] = validatePolicy(routeName, declared, options.defaults)
  })

  if (routesBeforePlugin !== null) {
    fastify.addHook('onReady', async () => {
      // A route the plugin never validated still gets `request.agent`, so it
      // looks policed while no policy can ever apply to it. Under 'strict'
      // -- the default -- boot stops here rather than shipping that state.
      if (options.registrationOrder === 'warn') {
        fastify.log.warn(
          { agentPolicy: { registrationOrder: 'warn', routesBeforePlugin } },
          `fastify-agent-policy was registered after these routes, so any agent policy they declare was never validated and can never be enforced:\n${routesBeforePlugin}`,
        )
        return
      }
      throw new RoutesBeforePluginError(routesBeforePlugin)
    })
  }

  // Identity resolution and the denial run in `onRequest`, the first hook in
  // the lifecycle. In `preHandler` they would run after body parsing and
  // schema validation, so an unidentified caller with a malformed body would
  // get Fastify's `400 FST_ERR_VALIDATION` in `application/json` instead of
  // the problem document.
  fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    // `request.routeOptions.config` is shared across every request on this
    // route. Read it; never write to it.
    const config = request.routeOptions.config as PolicedConfig | undefined
    const policy = config?.[kResolvedPolicy]

    let resolved: unknown
    try {
      resolved = await options.identify(request)
    } catch (error) {
      // The resolver's own message never reaches the caller: it may name
      // internal hosts or carry a token. It goes to the log instead.
      request.log.error({ err: error }, 'fastify-agent-policy: identify() failed')
      request.agent = null

      // A route that declares no policy never asked for one, so a failure in
      // the policy subsystem must not take it down with it. A policed route
      // fails closed: its policy cannot be honoured without an identity.
      if (policy === undefined) return

      return deny(request, reply, 'identify() failed', true)
    }

    // A resolver returning a malformed identity is a programming error, not a
    // transient failure, so it stays a 500 with this plugin's own message.
    request.agent = normalizeIdentity(resolved)

    if (policy === undefined) return
    if (request.agent !== null) return
    if (options.applyTo !== 'all') return

    return deny(request, reply, 'no agent identity resolved', false)
  })

  function deny(
    request: FastifyRequest,
    reply: FastifyReply,
    reason: string,
    retryable: boolean,
  ): FastifyReply {
    request.log.warn(
      {
        agentPolicy: {
          decision: 'denied',
          problem: 'agent_identity_required',
          reason,
          retryable,
          agent: request.agent?.id ?? null,
          method: request.method,
          url: request.url,
        },
      },
      'fastify-agent-policy denied the request',
    )

    return sendProblem(reply, 'agent_identity_required', {
      retryable,
      detail: retryable
        ? 'The agent identity could not be resolved right now. Retry the request.'
        : 'This route requires an identified agent caller. Present agent credentials your identify() resolver recognizes.',
    })
  }
}

export default fp(agentPolicy, {
  fastify: '5.x',
  name: 'fastify-agent-policy',
})
