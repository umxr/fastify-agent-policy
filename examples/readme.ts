/**
 * The README's examples, compiled. `npm run typecheck` covers this file and
 * `npm test` runs `typecheck` first, so the documented usage cannot drift
 * from the published types.
 */
import Fastify from 'fastify'

import agentPolicy, {
  DEFAULT_PROBLEM_BASE_URI,
  DEFAULT_WWW_AUTHENTICATE,
  PROBLEM_CONTENT_TYPE,
  PROBLEM_TYPES,
  bearerClaims,
  buildProblem,
  isValidProblemBaseUri,
  normalizeAgentOrigin,
  parseSignatureAgent,
  sendProblem,
  signatureAgent,
  userAgentPattern,
  validatePolicy,
  webBotAuth,
  type AgentIdentity,
  type ProblemKind,
  type RegistrationOrder,
  type ResolvedAgentPolicy,
} from '../src/index.ts'

const app = Fastify()

await app.register(agentPolicy, {
  // Identity is pluggable. `webBotAuth()` reads the verdict that
  // `fastify-web-bot-auth` leaves on the request.
  identify: webBotAuth(),
  // 'agents' (the default) leaves human traffic alone.
  applyTo: 'agents',
  // Every route inherits these unless it says otherwise.
  defaults: { risk: 'write' },
  problemBaseUri: 'https://api.example/problems',
  wwwAuthenticate: 'Signature realm="bots"',
  // 'strict' is the default; 'warn' and 'off' reopen the
  // silent-unpoliced-route hole.
  registrationOrder: 'strict',
})

app.post(
  '/orders/:id/refund',
  {
    config: {
      agent: {
        risk: 'destructive',
        scopes: ['orders:refund'],
        dryRun: 'handler',
        confirm: 'two-phase',
        guard: (_request, agent) => agent.class === 'trusted',
      },
    },
  },
  async (request) => {
    // `request.agent` is `AgentIdentity | null` on every request.
    const agent: AgentIdentity | null = request.agent
    return { refunded: true, by: agent?.id ?? 'human' }
  },
)

app.get('/orders/:id', { config: { agent: { risk: 'read' } } }, async (request) => {
  const caller: AgentIdentity | null = request.agent
  return { id: (request.params as { id: string }).id, caller: caller?.id ?? null }
})

// Building a denial from a hook of your own.
app.addHook('preHandler', async (request, reply) => {
  if (request.agent !== null && request.agent.id === 'https://blocked.example') {
    return sendProblem(reply, 'guard_failed', {
      retryable: false,
      detail: 'monthly call budget exhausted',
    })
  }
})

// The other three built-in resolvers.
const fromHeader = signatureAgent()
const fromClaims = bearerClaims<{ sub: string; scope?: string }>((claims) => ({
  id: claims.sub,
  scopes: claims.scope?.split(' '),
  class: 'verified',
}))
const fromUserAgent = userAgentPattern([/^(MyAgent)\/[\d.]+$/])

// The rest of the documented surface.
const kind: ProblemKind = PROBLEM_TYPES.scope_denied.slug
const document = buildProblem(kind, { requiredScopes: ['orders:refund'], retryable: false })
const contentType: string = PROBLEM_CONTENT_TYPE
const defaults: readonly [string, string] = [DEFAULT_PROBLEM_BASE_URI, DEFAULT_WWW_AUTHENTICATE]
const baseUriOk: boolean = isValidProblemBaseUri('https://api.example/problems')
const origin: string | null = normalizeAgentOrigin('https://Agent.Example/keys')
const rawAgent: string | null = parseSignatureAgent('sig="https://agent.example"')
const orders: readonly RegistrationOrder[] = ['strict', 'warn', 'off']
const policy: ResolvedAgentPolicy = validatePolicy(
  'POST /orders/:id/refund',
  { scopes: ['orders:refund'] },
  { risk: 'destructive' },
)

export {
  app,
  baseUriOk,
  contentType,
  defaults,
  document,
  fromClaims,
  fromHeader,
  fromUserAgent,
  orders,
  origin,
  policy,
  rawAgent,
}
