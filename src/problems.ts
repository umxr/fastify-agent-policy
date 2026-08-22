import createError from '@fastify/error'
import type { FastifyReply } from 'fastify'

/**
 * The eight denial types. All of them are defined now, on purpose: the error
 * contract is the product, and adding a type later would change a published
 * contract. Only `agent_identity_required` can fire in this release.
 */
export type ProblemKind =
  | 'scope_denied'
  | 'risk_tier_blocked'
  | 'guard_failed'
  | 'confirmation_required'
  | 'confirmation_invalid'
  | 'confirmation_expired'
  | 'dry_run_unsupported'
  | 'agent_identity_required'

/** One entry of {@link PROBLEM_TYPES}. */
export interface ProblemDefinition {
  /** The last path segment of the `type` URI. Stable; never renamed. */
  readonly slug: ProblemKind
  /** The HTTP status this denial always uses. */
  readonly status: number
  /** The human-readable `title` member. */
  readonly title: string
}

/**
 * Default base URI for `type` slugs. Per RFC 9457 a `type` URI identifies the
 * problem; it does not have to resolve. Override it with the plugin's
 * `problemBaseUri` option.
 */
export const DEFAULT_PROBLEM_BASE_URI = 'https://github.com/umxr/fastify-agent-policy/problems'

/** Instance state the plugin stashes on the Fastify instance. */
export const kAgentPolicyState = Symbol.for('fastify-agent-policy.state')

/** Shape stored under {@link kAgentPolicyState}. */
export interface AgentPolicyState {
  problemBaseUri: string
  /** The `WWW-Authenticate` challenge sent with a 401. */
  wwwAuthenticate: string
}

/**
 * Default `WWW-Authenticate` challenge. RFC 9110 section 11.6.1 makes the
 * header mandatory on a 401, and a challenge needs an auth scheme. Override
 * it with the plugin's `wwwAuthenticate` option when your identity scheme is
 * not a bearer token.
 */
export const DEFAULT_WWW_AUTHENTICATE = 'Bearer realm="agent-policy"'

/** Thrown when a problem type that does not exist is asked for. */
export const UnknownProblemKindError = createError<[string]>(
  'FST_AGENT_POLICY_UNKNOWN_PROBLEM',
  'Unknown agent policy problem type "%s"',
  500,
)

/**
 * Members that must never be copied out of an extensions object. Assigning
 * `__proto__` walks the prototype chain instead of adding a member, and
 * `constructor` / `prototype` are the neighbouring pollution vectors.
 */
const FORBIDDEN_EXTENSION_MEMBERS: readonly string[] = Object.freeze([
  '__proto__',
  'constructor',
  'prototype',
])

/** Members the problem type owns. An extension may not overwrite them. */
const RESERVED_MEMBERS: readonly string[] = Object.freeze(['type', 'title', 'status'])

/** The eight denial types, keyed by slug. Frozen -- the contract is stable. */
export const PROBLEM_TYPES: Readonly<Record<ProblemKind, ProblemDefinition>> = Object.freeze({
  scope_denied: Object.freeze({
    slug: 'scope_denied',
    status: 403,
    title: 'Agent scope denied',
  }),
  risk_tier_blocked: Object.freeze({
    slug: 'risk_tier_blocked',
    status: 403,
    title: 'Agent risk tier blocked',
  }),
  guard_failed: Object.freeze({
    slug: 'guard_failed',
    status: 403,
    title: 'Agent guard failed',
  }),
  confirmation_required: Object.freeze({
    slug: 'confirmation_required',
    status: 409,
    title: 'Agent confirmation required',
  }),
  confirmation_invalid: Object.freeze({
    slug: 'confirmation_invalid',
    status: 409,
    title: 'Agent confirmation invalid',
  }),
  confirmation_expired: Object.freeze({
    slug: 'confirmation_expired',
    status: 409,
    title: 'Agent confirmation expired',
  }),
  dry_run_unsupported: Object.freeze({
    slug: 'dry_run_unsupported',
    status: 400,
    title: 'Dry run unsupported',
  }),
  agent_identity_required: Object.freeze({
    slug: 'agent_identity_required',
    status: 401,
    title: 'Agent identity required',
  }),
} satisfies Record<ProblemKind, ProblemDefinition>)

/** The RFC 9457 media type. */
export const PROBLEM_CONTENT_TYPE = 'application/problem+json'

/**
 * Extension members a denial may carry. RFC 9457 allows any additional
 * member; these four are the documented ones.
 */
export interface ProblemExtensions {
  /** Scopes the route wanted. Sent with `scope_denied`. */
  requiredScopes?: string[]
  /** Token for phase two. Sent with `confirmation_required`. */
  confirmationToken?: string
  /** Seconds until `confirmationToken` expires. */
  expiresIn?: number
  /** Whether repeating the same request unchanged can ever succeed. */
  retryable?: boolean
  /** Human-readable explanation of this occurrence. */
  detail?: string
  /** URI reference identifying this occurrence. */
  instance?: string
  [member: string]: unknown
}

/** A serialized RFC 9457 problem document. */
export interface ProblemDocument {
  type: string
  title: string
  status: number
  detail?: string
  instance?: string
  [member: string]: unknown
}

function joinBaseUri(baseUri: string, slug: string): string {
  return `${baseUri.replace(/\/+$/, '')}/${slug}`
}

/**
 * Whether `value` can carry the `type` slugs.
 *
 * RFC 9457 requires `type` to be a URI reference, so a base that `new URL()`
 * refuses would ship a malformed contract. Checked at registration, never at
 * request time.
 */
export function isValidProblemBaseUri(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0) return false
  try {
    // eslint-disable-next-line no-new
    new URL(value)
    return true
  } catch {
    return false
  }
}

/**
 * Builds the problem document for `kind`.
 *
 * Every member of an RFC 9457 document is optional, and an absent `type`
 * means `about:blank`. So `type`, `title` and `status` are always emitted.
 */
export function buildProblem(
  kind: ProblemKind,
  extensions: ProblemExtensions = {},
  baseUri: string = DEFAULT_PROBLEM_BASE_URI,
): ProblemDocument {
  const definition = PROBLEM_TYPES[kind]
  if (definition === undefined) {
    // Without this the next line throws a bare TypeError from inside a
    // response, which tells an operator nothing about which call was wrong.
    throw new UnknownProblemKindError(String(kind))
  }

  const document: ProblemDocument = {
    type: joinBaseUri(baseUri, definition.slug),
    title: definition.title,
    status: definition.status,
  }

  for (const [member, value] of Object.entries(extensions)) {
    if (value === undefined) continue
    if (RESERVED_MEMBERS.includes(member)) continue
    if (FORBIDDEN_EXTENSION_MEMBERS.includes(member)) continue
    document[member] = value
  }

  return document
}

/**
 * Sends a denial.
 *
 * Denials are sent, never thrown. A host application's root
 * `setErrorHandler` intercepts thrown errors and rewrites the body to
 * `application/json`, which silently breaks the contract agents read.
 *
 * Return the result from your hook so Fastify stops the lifecycle.
 */
export function sendProblem(
  reply: FastifyReply,
  kind: ProblemKind,
  extensions: ProblemExtensions = {},
): FastifyReply {
  const state = (reply.server as unknown as Record<symbol, AgentPolicyState | undefined>)[
    kAgentPolicyState
  ]
  const document = buildProblem(kind, extensions, state?.problemBaseUri ?? DEFAULT_PROBLEM_BASE_URI)

  reply.code(document.status).type(PROBLEM_CONTENT_TYPE)

  // RFC 9110 section 11.6.1: a 401 must carry a challenge.
  if (document.status === 401 && reply.getHeader('www-authenticate') === undefined) {
    reply.header('WWW-Authenticate', state?.wwwAuthenticate ?? DEFAULT_WWW_AUTHENTICATE)
  }

  // The document must reach the caller byte-for-byte. Without this, a route
  // that declares `schema.response[401]` serializes the denial through its
  // own schema and strips it to `{}` while the content type still claims
  // `application/problem+json`. A reply serializer takes priority over the
  // route's, so the contract survives whatever the route declares.
  reply.serializer(JSON.stringify)

  reply.send(document)
  return reply
}
