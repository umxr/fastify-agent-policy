import assert from 'node:assert/strict'
import test from 'node:test'

import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

import agentPolicy, {
  PROBLEM_CONTENT_TYPE,
  type AgentIdentity,
  type AgentPolicy,
  type AgentPolicyOptions,
} from '../src/index.ts'

// Reached directly, not through the package root: the normalizer is internal,
// and the request path's fail-closed fallback re-derives from it.
import { normalizeScopeRequirement } from '../src/enforce.ts'

const PROBLEM_BASE = 'https://github.com/umxr/fastify-agent-policy/problems'

/** Collects everything the app logs, as parsed pino records. */
function captureLogs(): {
  records: Array<Record<string, unknown>>
  stream: { write(line: string): void }
} {
  const records: Array<Record<string, unknown>> = []
  return {
    records,
    stream: {
      write(line: string) {
        records.push(JSON.parse(line) as Record<string, unknown>)
      },
    },
  }
}

/**
 * Reads the identity out of headers, the way `test/identity.test.ts` does:
 * `x-agent-id` is the id, `x-agent-class` the class, and `x-agent-scopes` a
 * space-separated scope list. Absent `x-agent-id` means human traffic.
 */
function headerResolver(request: FastifyRequest): AgentIdentity | null {
  const id = request.headers['x-agent-id']
  if (typeof id !== 'string' || id.length === 0) return null

  const agentClass = request.headers['x-agent-class']
  const scopes = request.headers['x-agent-scopes']

  return {
    id,
    class: typeof agentClass === 'string' ? agentClass : 'verified',
    scopes: typeof scopes === 'string' && scopes.length > 0 ? scopes.split(' ') : [],
  }
}

/** Tracks whether the handler ran, so a denial can be proved to stop it. */
interface Probe {
  app: FastifyInstance
  ran: () => boolean
}

function build(
  policy: AgentPolicy,
  options: Partial<AgentPolicyOptions> = {},
  logStream?: { write(line: string): void },
  schema?: Record<string, unknown>,
): Probe {
  let ran = false
  const app = logStream === undefined ? Fastify() : Fastify({ logger: { level: 'trace', stream: logStream } })

  app.register(agentPolicy, { identify: headerResolver, ...options })
  app.register(async (routes) => {
    routes.post('/orders/:id/refund', { config: { agent: policy }, schema }, async () => {
      ran = true
      return { ok: true }
    })
  })

  return { app, ran: () => ran }
}

/** What `app.inject()` resolves to. */
type Injected = Awaited<ReturnType<FastifyInstance['inject']>>

/** Calls the policed route as an agent with this class and these scopes. */
function callAs(
  app: FastifyInstance,
  agent: { id?: string; class?: string; scopes?: string } | null,
  payload?: object,
): Promise<Injected> {
  const headers: Record<string, string> = {}
  if (agent !== null) {
    headers['x-agent-id'] = agent.id ?? 'https://agent.example'
    if (agent.class !== undefined) headers['x-agent-class'] = agent.class
    if (agent.scopes !== undefined) headers['x-agent-scopes'] = agent.scopes
  }
  return app.inject({ method: 'POST', url: '/orders/1/refund', headers, payload })
}

/** The `agentPolicy` record of the first denial the app logged. */
function denialRecord(records: Array<Record<string, unknown>>): Record<string, unknown> {
  const denial = records.find(
    (record) => (record['agentPolicy'] as Record<string, unknown> | undefined)?.['decision'] === 'denied',
  )
  assert.ok(denial, 'a denial was logged')
  return denial['agentPolicy'] as Record<string, unknown>
}

/** Asserts the response is the denial document for `slug`. */
function assertProblem(response: Injected, slug: string): Record<string, unknown> {
  assert.equal(response.statusCode, 403)
  assert.equal(response.headers['content-type'], PROBLEM_CONTENT_TYPE)
  // A 403 is not a 401, so it must not carry a challenge.
  assert.equal(response.headers['www-authenticate'], undefined)

  const body = response.json()
  assert.equal(body['type'], `${PROBLEM_BASE}/${slug}`)
  assert.equal(body['status'], 403)
  return body
}

// --- Matrix: all checks pass -------------------------------------------------

test('all checks pass: the handler runs', async () => {
  const { app, ran } = build(
    {
      risk: 'destructive',
      scopes: ['orders:refund'],
      guard: (_request, agent) => agent.class === 'trusted',
    },
    { maxRisk: { trusted: 'destructive' } },
  )

  const response = await callAs(app, { class: 'trusted', scopes: 'orders:refund orders:read' })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { ok: true })
  assert.equal(ran(), true)
  await app.close()
})

// --- Matrix: risk tiers ------------------------------------------------------

test('tier exceeded: a destructive route refuses a class allowed only write', async () => {
  const { app, ran } = build({ risk: 'destructive' }, { maxRisk: { verified: 'write' } })

  const response = await callAs(app, { class: 'verified' })

  const body = assertProblem(response, 'risk_tier_blocked')
  assert.equal(body['title'], 'Agent risk tier blocked')
  assert.equal(body['retryable'], false)
  assert.equal(ran(), false, 'the handler never ran')
  await app.close()
})

test('the allowance is inclusive: a write route accepts a class allowed write', async () => {
  const { app, ran } = build({ risk: 'write' }, { maxRisk: { verified: 'write' } })

  const response = await callAs(app, { class: 'verified' })

  assert.equal(response.statusCode, 200)
  assert.equal(ran(), true)
  await app.close()
})

test('unlisted class: the "default" allowance applies', async () => {
  const { app, ran } = build({ risk: 'read' }, { maxRisk: { trusted: 'destructive', default: 'read' } })

  const response = await callAs(app, { class: 'partner-bot' })

  assert.equal(response.statusCode, 200)
  assert.equal(ran(), true)
  await app.close()
})

test('unlisted class: the "default" allowance also binds it', async () => {
  const { app, ran } = build({ risk: 'destructive' }, { maxRisk: { trusted: 'destructive', default: 'read' } })

  const response = await callAs(app, { class: 'partner-bot' })

  assertProblem(response, 'risk_tier_blocked')
  assert.equal(ran(), false)
  await app.close()
})

test('unlisted class and no default: the request fails closed', async () => {
  // The lowest tier there is, so nothing but the missing allowance can deny it.
  const { app, ran } = build({ risk: 'read' }, { maxRisk: { trusted: 'destructive' } })

  const response = await callAs(app, { class: 'partner-bot' })

  const body = assertProblem(response, 'risk_tier_blocked')
  assert.equal(body['retryable'], false)
  assert.equal(ran(), false)
  await app.close()
})

test('an identity with no class and no default fails closed', async () => {
  const app = Fastify()
  app.register(agentPolicy, {
    identify: () => ({ id: 'https://agent.example' }),
    maxRisk: { trusted: 'destructive' },
  })
  app.register(async (routes) => {
    routes.get('/x', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
  })

  const response = await app.inject({ method: 'GET', url: '/x' })
  assertProblem(response, 'risk_tier_blocked')
  await app.close()
})

test('a class named like an Object member falls through to the default allowance', async () => {
  // The map deliberately carries ONLY `default`, so the fail-closed branch
  // cannot answer for it: if the null prototype did not hold, a plain literal
  // would answer `maxRisk['constructor']` with `Object`, take that function as
  // the granted tier, and `RISK_ORDER['read'] <= undefined` would deny. A 200
  // here is only reachable because the lookup found nothing and fell through.
  for (const hostile of ['constructor', 'toString', '__proto__', 'hasOwnProperty', 'valueOf']) {
    const { app, ran } = build({ risk: 'read' }, { maxRisk: { default: 'read' } })

    const response = await callAs(app, { class: hostile })

    assert.equal(response.statusCode, 200, `class ${hostile} should take the default allowance`)
    assert.equal(ran(), true)
    await app.close()
  }
})

test('a prototype-named class is still bound by the default allowance', async () => {
  // The other half: falling through to `default` must not mean escaping it.
  const { app, ran } = build({ risk: 'destructive' }, { maxRisk: { default: 'read' } })

  assertProblem(await callAs(app, { class: 'constructor' }), 'risk_tier_blocked')
  assert.equal(ran(), false)
  await app.close()
})

test('no maxRisk at all: the tier check is skipped and scopes still run', async () => {
  const { app, ran } = build({ risk: 'destructive', scopes: ['orders:refund'] })

  const allowed = await callAs(app, { class: 'anything-at-all', scopes: 'orders:refund' })
  assert.equal(allowed.statusCode, 200, 'no maxRisk means no tier ceiling')
  assert.equal(ran(), true)

  const denied = await callAs(app, { class: 'anything-at-all', scopes: 'orders:read' })
  assertProblem(denied, 'scope_denied')
  await app.close()
})

test('no maxRisk at all: the guard still runs', async () => {
  const { app } = build({
    risk: 'destructive',
    guard: () => ({ allow: false, reason: 'over limit' }),
  })

  const response = await callAs(app, {})
  const body = assertProblem(response, 'guard_failed')
  assert.equal(body['detail'], 'over limit')
  await app.close()
})

test('the maxRisk allowance is logged in full and disclosed to nobody', async () => {
  const { records, stream } = captureLogs()
  const { app } = build({ risk: 'destructive' }, { maxRisk: { verified: 'read' } }, stream)

  const response = await callAs(app, { class: 'verified' })
  const body = assertProblem(response, 'risk_tier_blocked')

  // The operator gets the whole picture: which tier, which allowance, which
  // class. Asserting the reason positively is what makes the absence below
  // mean something -- a bare `!includes` would also pass if the reason were
  // never built.
  const entry = denialRecord(records)
  assert.equal(entry['problem'], 'risk_tier_blocked')
  assert.equal(
    entry['reason'],
    'route risk "destructive" exceeds the "read" allowance for agent class "verified"',
  )

  // The caller gets none of it. Checked against the parsed detail rather than
  // the raw JSON, so a prose mention would not slip past a quoted match.
  const detail = String(body['detail'])
  for (const secret of ['read', 'write', 'destructive', 'verified', 'allowance']) {
    assert.ok(!detail.includes(secret), `detail must not mention ${secret}`)
  }
  await app.close()
})

test('the tier ordering is read < write < destructive across every combination', async () => {
  // Pins the ordering derived from RISK_TIERS. Reordering that array would
  // silently widen an allowance, and this is the test that would notice.
  const tiers = ['read', 'write', 'destructive'] as const
  const expected: Record<string, boolean> = {
    'read|read': true, 'read|write': true, 'read|destructive': true,
    'write|read': false, 'write|write': true, 'write|destructive': true,
    'destructive|read': false, 'destructive|write': false, 'destructive|destructive': true,
  }

  for (const risk of tiers) {
    for (const allowance of tiers) {
      const { app } = build({ risk }, { maxRisk: { verified: allowance } })
      const response = await callAs(app, { class: 'verified' })
      const allowed = response.statusCode === 200

      assert.equal(
        allowed,
        expected[`${risk}|${allowance}`],
        `risk ${risk} under allowance ${allowance} should be ${expected[`${risk}|${allowance}`] ? 'allowed' : 'denied'}`,
      )
      await app.close()
    }
  }
})

// --- Matrix: scopes ----------------------------------------------------------

test('scopes unsatisfied: 403 scope_denied carrying requiredScopes', async () => {
  const { app, ran } = build({ risk: 'write', scopes: ['orders:refund'] })

  const response = await callAs(app, { scopes: 'orders:read' })

  const body = assertProblem(response, 'scope_denied')
  assert.equal(body['title'], 'Agent scope denied')
  assert.deepEqual(body['requiredScopes'], ['orders:refund'])
  assert.equal(body['retryable'], false)
  assert.equal(ran(), false, 'the handler never ran')
  await app.close()
})

test('an agent holding no scopes at all is denied', async () => {
  const { app, ran } = build({ risk: 'write', scopes: ['orders:refund'] })

  const response = await callAs(app, {})

  assertProblem(response, 'scope_denied')
  assert.equal(ran(), false)
  await app.close()
})

test('a bare array is all-of: holding one of two is not enough', async () => {
  const { app } = build({ risk: 'write', scopes: ['orders:refund', 'orders:read'] })

  const partial = await callAs(app, { scopes: 'orders:refund' })
  const body = assertProblem(partial, 'scope_denied')
  assert.deepEqual(body['requiredScopes'], ['orders:refund', 'orders:read'])

  const complete = await callAs(app, { scopes: 'orders:read orders:refund' })
  assert.equal(complete.statusCode, 200)
  await app.close()
})

test('{ all } behaves the same as the bare array', async () => {
  const { app } = build({ risk: 'write', scopes: { all: ['a', 'b'] } })

  assertProblem(await callAs(app, { scopes: 'a' }), 'scope_denied')
  assert.equal((await callAs(app, { scopes: 'a b' })).statusCode, 200)
  await app.close()
})

test('any-of satisfied: holding one member is enough', async () => {
  const { app, ran } = build({ risk: 'write', scopes: { any: ['a', 'b'] } })

  const response = await callAs(app, { scopes: 'b' })

  assert.equal(response.statusCode, 200)
  assert.equal(ran(), true)
  await app.close()
})

test('any-of unsatisfied: holding neither member is denied', async () => {
  const { app } = build({ risk: 'write', scopes: { any: ['a', 'b'] } })

  const body = assertProblem(await callAs(app, { scopes: 'c' }), 'scope_denied')
  assert.deepEqual(body['requiredScopes'], ['a', 'b'])
  await app.close()
})

test('scopes match by exact string equality: no prefixes, no wildcards', async () => {
  const { app } = build({ risk: 'write', scopes: ['orders:refund'] })

  // A hierarchy rule would let each of these through. There is no hierarchy.
  assertProblem(await callAs(app, { scopes: 'orders' }), 'scope_denied')
  assertProblem(await callAs(app, { scopes: 'orders:*' }), 'scope_denied')
  assertProblem(await callAs(app, { scopes: 'orders:refund:all' }), 'scope_denied')
  assertProblem(await callAs(app, { scopes: 'ORDERS:REFUND' }), 'scope_denied')

  assert.equal((await callAs(app, { scopes: 'orders:refund' })).statusCode, 200)
  await app.close()
})

test('defaults.scopes are replaced by a route\'s own scopes, never unioned', async () => {
  const { app } = build({ risk: 'write', scopes: ['orders:refund'] }, { defaults: { scopes: ['tenant:acme'] } })

  // The shallow merge means only the route's list applies.
  const response = await callAs(app, { scopes: 'orders:refund' })
  assert.equal(response.statusCode, 200)
  await app.close()
})

// --- Matrix: guards ----------------------------------------------------------

test('guard denies: 403 guard_failed with the reason as detail', async () => {
  const { app, ran } = build({
    risk: 'write',
    guard: () => ({ allow: false, reason: 'over limit' }),
  })

  const response = await callAs(app, {})

  const body = assertProblem(response, 'guard_failed')
  assert.equal(body['title'], 'Agent guard failed')
  assert.equal(body['detail'], 'over limit')
  assert.equal(body['retryable'], false)
  assert.equal(ran(), false, 'the handler never ran')
  await app.close()
})

test('a guard denial logs the same reason it publishes', async () => {
  const { records, stream } = captureLogs()
  const { app } = build({ risk: 'write', guard: () => ({ allow: false, reason: 'over limit' }) }, {}, stream)

  const body = assertProblem(await callAs(app, {}), 'guard_failed')
  const entry = denialRecord(records)

  assert.equal(entry['problem'], 'guard_failed')
  assert.equal(entry['reason'], 'over limit')
  assert.equal(entry['retryable'], false)
  assert.equal(body['detail'], entry['reason'], 'a stated refusal is not a secret')
  await app.close()
})

test('guard returning false denies without a detail of its own', async () => {
  const { app } = build({ risk: 'write', guard: () => false })

  const body = assertProblem(await callAs(app, {}), 'guard_failed')
  assert.equal(typeof body['detail'], 'string')
  await app.close()
})

test('guard returning true allows, and { allow: true } does too', async () => {
  const boolean = build({ risk: 'write', guard: () => true })
  assert.equal((await callAs(boolean.app, {})).statusCode, 200)
  await boolean.app.close()

  const object = build({ risk: 'write', guard: async () => ({ allow: true }) })
  assert.equal((await callAs(object.app, {})).statusCode, 200)
  await object.app.close()
})

test('a guard that returns neither shape is treated as a denial', async () => {
  const { app, ran } = build({
    risk: 'write',
    guard: (() => undefined) as unknown as AgentPolicy['guard'],
  })

  assertProblem(await callAs(app, {}), 'guard_failed')
  assert.equal(ran(), false)
  await app.close()
})

test('the guard receives the request and the identity', async () => {
  let seen: { url: string; id: string } | null = null
  const { app } = build({
    risk: 'write',
    guard: (request, agent) => {
      seen = { url: request.url, id: agent.id }
      return true
    },
  })

  await callAs(app, { id: 'https://bot.example' })

  assert.deepEqual(seen, { url: '/orders/1/refund', id: 'https://bot.example' })
  await app.close()
})

test('guard throws: 403 guard_failed, retryable, and the message stays in the log', async () => {
  const { records, stream } = captureLogs()
  const { app, ran } = build(
    {
      risk: 'write',
      guard: async () => {
        throw new Error('redis://secret-host:6379 refused the connection')
      },
    },
    {},
    stream,
  )

  const response = await callAs(app, {})

  const body = assertProblem(response, 'guard_failed')
  assert.equal(body['retryable'], true)
  assert.ok(!response.body.includes('secret-host'), 'the guard message never reaches the caller')
  assert.equal(ran(), false, 'the handler never ran')

  const logged = records.find((record) => record['level'] === 50)
  assert.ok(logged, 'the failure was logged at error level')
  assert.match(JSON.stringify((logged['err'] as Record<string, unknown>)?.['message']), /secret-host/)
  await app.close()
})

test('a thrown guard is logged with its own reason and denies as undecidable', async () => {
  const { records, stream } = captureLogs()
  const { app } = build(
    {
      risk: 'write',
      guard: () => {
        throw new Error('postgres://user:pw@internal-db/refunds timed out')
      },
    },
    {},
    stream,
  )

  const body = assertProblem(await callAs(app, {}), 'guard_failed')

  const entry = denialRecord(records)
  assert.equal(entry['problem'], 'guard_failed')
  assert.equal(entry['reason'], 'guard() failed')
  assert.equal(entry['retryable'], true)

  // retryable distinguishes "could not decide" from "decided no". The status
  // stays 403 either way -- guard_failed's status is frozen in the published
  // type table, so an undecidable guard does not become a 5xx.
  assert.equal(body['status'], 403)
  assert.equal(body['retryable'], true)
  assert.ok(!String(body['detail']).includes('internal-db'))
  await app.close()
})

test('a guard reason is capped and stripped of control characters', async () => {
  const noisy = `over\u0000 limit\u001b[31m\n\tby $${'9'.repeat(400)}`
  const { app } = build({ risk: 'write', guard: () => ({ allow: false, reason: noisy }) })

  const detail = String(assertProblem(await callAs(app, {}), 'guard_failed')['detail'])

  assert.ok(detail.length <= 200, `detail was ${detail.length} characters`)
  assert.equal(detail.slice(0, 10), 'over limit')
  assert.ok(!/[\u0000-\u001f\u007f-\u009f]/.test(detail), 'no control characters survive')
  assert.ok(detail.endsWith('\u2026'), 'a truncated reason is marked as truncated')
  await app.close()
})

test('a guard reason of only control characters falls back to the generic detail', async () => {
  const { app } = build({ risk: 'write', guard: () => ({ allow: false, reason: '\u0000\u001b  ' }) })

  const detail = String(assertProblem(await callAs(app, {}), 'guard_failed')['detail'])
  assert.equal(detail, 'The guard for this route refused the request.')
  await app.close()
})

// --- Matrix: the guard reads the body ---------------------------------------

test('a guard reads request.body and its verdict is honoured', async () => {
  // The brief's headline example. In `onRequest` the body is not parsed yet,
  // so this guard would read `undefined` and refuse every valid call.
  const { app, ran } = build({
    risk: 'destructive',
    guard: (request) => {
      const body = request.body as { amount?: number } | undefined
      if (body === undefined) return { allow: false, reason: 'the guard could not see a body' }
      return (body.amount ?? 0) <= 500
    },
  })

  const small = await callAs(app, {}, { amount: 100 })
  assert.equal(small.statusCode, 200, 'a within-limit body is allowed')
  assert.equal(ran(), true)

  const large = await callAs(app, {}, { amount: 900 })
  assertProblem(large, 'guard_failed')
  await app.close()
})

test('a body failing schema validation 400s before the guard runs', async () => {
  // The accepted cost of moving the guard to preHandler: Fastify's validation
  // is the earlier gate. The denial contract is unaffected, because a caller
  // that fails validation was never going to reach the handler either.
  let guardRan = false
  const { app } = build(
    {
      risk: 'write',
      guard: () => {
        guardRan = true
        return true
      },
    },
    {},
    undefined,
    { body: { type: 'object', required: ['amount'], properties: { amount: { type: 'number' } } } },
  )

  const response = await callAs(app, {}, { wrong: 'shape' })

  assert.equal(response.statusCode, 400)
  assert.equal(guardRan, false)
  await app.close()
})

// --- Matrix: anonymous traffic ----------------------------------------------

test('anonymous under applyTo "agents": the handler runs and nothing is checked', async () => {
  // Every check would deny this caller if it ran: the tier is above any
  // allowance, the scopes are unheld, and the guard always refuses.
  const { app, ran } = build(
    {
      risk: 'destructive',
      scopes: ['orders:refund'],
      guard: () => ({ allow: false, reason: 'never' }),
    },
    { applyTo: 'agents', maxRisk: { default: 'read' } },
  )

  const response = await callAs(app, null)

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { ok: true })
  assert.equal(ran(), true)
  await app.close()
})

test('anonymous under applyTo "all" is still an identity denial, not a policy one', async () => {
  const { app } = build({ risk: 'destructive', scopes: ['orders:refund'] }, { applyTo: 'all' })

  const response = await callAs(app, null)

  assert.equal(response.statusCode, 401)
  assert.equal(response.json()['type'], `${PROBLEM_BASE}/agent_identity_required`)
  await app.close()
})

test('a route with no policy is never enforced against', async () => {
  const app = Fastify()
  app.register(agentPolicy, { identify: headerResolver, maxRisk: { default: 'read' } })
  app.register(async (routes) => {
    routes.get('/open', async (request) => ({ agent: request.agent?.id ?? null }))
  })

  const response = await app.inject({
    method: 'GET',
    url: '/open',
    headers: { 'x-agent-id': 'https://agent.example', 'x-agent-class': 'unknown-class' },
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { agent: 'https://agent.example' })
  await app.close()
})

// --- Matrix: order -----------------------------------------------------------

test('order is deterministic: failing the tier and the scopes yields risk_tier_blocked', async () => {
  const { app } = build(
    { risk: 'destructive', scopes: ['orders:refund'] },
    { maxRisk: { verified: 'read' } },
  )

  // Holds none of the scopes either, so both checks would deny.
  const response = await callAs(app, { class: 'verified', scopes: 'nothing:useful' })

  assertProblem(response, 'risk_tier_blocked')
  await app.close()
})

test('order is deterministic: the guard never runs while the scopes fail', async () => {
  let guardRan = false
  const { app } = build({
    risk: 'write',
    scopes: ['orders:refund'],
    guard: () => {
      guardRan = true
      return true
    },
  })

  const response = await callAs(app, { scopes: 'orders:read' })

  assertProblem(response, 'scope_denied')
  assert.equal(guardRan, false, 'the guard is the last and most expensive check')
  await app.close()
})

test('order is deterministic: the guard never runs while the tier fails', async () => {
  let guardRan = false
  const { app } = build(
    {
      risk: 'destructive',
      guard: () => {
        guardRan = true
        return true
      },
    },
    { maxRisk: { verified: 'read' } },
  )

  assertProblem(await callAs(app, { class: 'verified' }), 'risk_tier_blocked')
  assert.equal(guardRan, false)
  await app.close()
})

// --- The denial log ----------------------------------------------------------

test('an enforcement denial is logged with the problem type, the agent and the route', async () => {
  const { records, stream } = captureLogs()
  const { app } = build({ risk: 'write', scopes: ['orders:refund'] }, {}, stream)

  await callAs(app, { id: 'https://bot.example', scopes: 'orders:read' })

  const denial = records.find(
    (record) => (record['agentPolicy'] as Record<string, unknown> | undefined)?.['decision'] === 'denied',
  )
  assert.ok(denial, 'a denial was logged')
  const entry = denial['agentPolicy'] as Record<string, unknown>
  assert.equal(entry['problem'], 'scope_denied')
  assert.equal(entry['agent'], 'https://bot.example')
  assert.equal(entry['method'], 'POST')
  assert.equal(entry['url'], '/orders/1/refund')
  assert.equal(entry['retryable'], false)
  await app.close()
})

// --- Matrix: inherited requirements -----------------------------------------

test('defaults.scopes are inherited by a route that declares none', async () => {
  // The route declares an empty policy, so the requirement can only have come
  // from `defaults`. A test where the route restates the scopes would pass
  // even if inheritance were broken entirely.
  const { app, ran } = build({}, { defaults: { risk: 'write', scopes: ['tenant:acme'] } })

  const denied = await callAs(app, { scopes: 'orders:read' })
  const body = assertProblem(denied, 'scope_denied')
  assert.deepEqual(body['requiredScopes'], ['tenant:acme'], 'the inherited list is reported')
  assert.equal(ran(), false)

  const allowed = await callAs(app, { scopes: 'tenant:acme' })
  assert.equal(allowed.statusCode, 200)
  await app.close()
})

test('defaults.guard is inherited by a route that declares none', async () => {
  let guardRan = false
  const { app, ran } = build(
    {},
    {
      defaults: {
        risk: 'write',
        guard: () => {
          guardRan = true
          return { allow: false, reason: 'inherited guard said no' }
        },
      },
    },
  )

  const body = assertProblem(await callAs(app, {}), 'guard_failed')

  assert.equal(guardRan, true, 'the inherited guard actually ran')
  assert.equal(body['detail'], 'inherited guard said no')
  assert.equal(ran(), false)
  await app.close()
})

test('defaults.risk is inherited and checked against maxRisk', async () => {
  const { app, ran } = build({}, { defaults: { risk: 'destructive' }, maxRisk: { verified: 'write' } })

  assertProblem(await callAs(app, { class: 'verified' }), 'risk_tier_blocked')
  assert.equal(ran(), false)
  await app.close()
})

// --- Matrix: an identity with no scopes member ------------------------------

test('an identity with no scopes property at all is denied, not waved through', async () => {
  // What every built-in resolver emits unless it is configured with scopes.
  // A fail-open regression here would let every default-configured resolver
  // satisfy every scope requirement, and a suite that only ever passes
  // `scopes: []` would not notice.
  let ran = false
  const app = Fastify()
  app.register(agentPolicy, { identify: () => ({ id: 'https://agent.example' }) })
  app.register(async (routes) => {
    routes.get('/reports', { config: { agent: { risk: 'read', scopes: ['reports:read'] } } }, async () => {
      ran = true
      return { ok: true }
    })
  })

  const response = await app.inject({ method: 'GET', url: '/reports' })

  assert.equal(response.statusCode, 403)
  assert.equal(
    response.json()['type'],
    `${PROBLEM_BASE}/scope_denied`,
    'an absent scopes member is not an empty requirement',
  )
  assert.deepEqual(response.json()['requiredScopes'], ['reports:read'])
  assert.equal(ran, false)
  await app.close()
})

test('an identity with no scopes still passes a route that requires none', async () => {
  const app = Fastify()
  app.register(agentPolicy, { identify: () => ({ id: 'https://agent.example' }) })
  app.register(async (routes) => {
    routes.get('/reports', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
  })

  assert.equal((await app.inject({ method: 'GET', url: '/reports' })).statusCode, 200)
  await app.close()
})

// --- Guard results that are truthy but not `true` ---------------------------

test('a guard whose allow is truthy but not true denies', async () => {
  // Relaxing `answer.allow === true` to `answer.allow` would grant on every
  // one of these, and would ship green without this test.
  const results: unknown[] = [
    { allow: 'yes' },
    { allow: 1 },
    { allow: 'false' },
    { allow: {} },
    { allow: [] },
    { ok: true },
    { allowed: true },
    {},
    { allow: null },
  ]

  for (const result of results) {
    const { app, ran } = build({
      risk: 'write',
      guard: (() => result) as unknown as AgentPolicy['guard'],
    })

    const response = await callAs(app, {})
    assertProblem(response, 'guard_failed')
    assert.equal(ran(), false, `${JSON.stringify(result)} must not allow the handler to run`)
    await app.close()
  }
})

test('only a boolean true or an allow of exactly true permits', async () => {
  for (const result of [true, { allow: true }, { allow: true, reason: 'ignored when allowing' }]) {
    const { app } = build({ risk: 'write', guard: (() => result) as unknown as AgentPolicy['guard'] })
    assert.equal((await callAs(app, {})).statusCode, 200, `${JSON.stringify(result)} should allow`)
    await app.close()
  }
})

// --- The fourth cell of the applyTo matrix ----------------------------------

test('an identified caller under applyTo "all" is checked like any other', async () => {
  const { app, ran } = build(
    { risk: 'write', scopes: ['orders:refund'] },
    { applyTo: 'all', maxRisk: { verified: 'write' } },
  )

  // Identified and satisfying every check: `applyTo: 'all'` adds nothing.
  const allowed = await callAs(app, { scopes: 'orders:refund' })
  assert.equal(allowed.statusCode, 200)
  assert.equal(ran(), true)

  // Identified but lacking the scope: a policy denial, not an identity one.
  const denied = await callAs(app, { scopes: 'orders:read' })
  assertProblem(denied, 'scope_denied')
  await app.close()
})

// --- The two identity denials are published strings -------------------------

test('both agent_identity_required details are exactly as published', async () => {
  const missing = build({ risk: 'read' }, { applyTo: 'all' })
  const missingBody = (await callAs(missing.app, null)).json()
  assert.equal(missingBody['status'], 401)
  assert.equal(
    missingBody['detail'],
    'This route requires an identified agent caller. Present agent credentials your identify() resolver recognizes.',
  )
  assert.equal(missingBody['retryable'], false)
  await missing.app.close()

  const broken = Fastify()
  broken.register(agentPolicy, {
    identify: () => {
      throw new Error('resolver is down')
    },
  })
  broken.register(async (routes) => {
    routes.get('/x', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
  })
  const brokenBody = (await broken.inject({ method: 'GET', url: '/x' })).json()
  assert.equal(brokenBody['status'], 401)
  assert.equal(
    brokenBody['detail'],
    'The agent identity could not be resolved right now. Retry the request.',
  )
  assert.equal(brokenBody['retryable'], true)
  await broken.close()
})

// --- The scope requirement never reads as absent ----------------------------

test('normalizeScopeRequirement distinguishes "no scopes" from every real requirement', async () => {
  // The request path caches this under a private symbol and re-derives it if
  // the cache is missing. `null` is the honest "this route requires nothing";
  // it is the only input that may produce it, so a missing cache can never be
  // mistaken for an unpoliced route.
  assert.equal(normalizeScopeRequirement(undefined), null)

  assert.deepEqual({ ...normalizeScopeRequirement(['a', 'b']) }, {
    mode: 'all',
    scopes: ['a', 'b'],
  })
  assert.deepEqual({ ...normalizeScopeRequirement({ all: ['a'] }) }, { mode: 'all', scopes: ['a'] })
  assert.deepEqual({ ...normalizeScopeRequirement({ any: ['a'] }) }, { mode: 'any', scopes: ['a'] })
})

test('the normalized requirement is a frozen copy, not a view of the route config', async () => {
  const declared = ['orders:refund']
  const normalized = normalizeScopeRequirement(declared)

  assert.ok(normalized !== null)
  // `routeOptions.config` is read-only at request time; mutating what the
  // caller declared must not retarget an already-registered route.
  declared.push('orders:admin')
  assert.deepEqual([...normalized.scopes], ['orders:refund'])
  assert.ok(Object.isFrozen(normalized))
  assert.ok(Object.isFrozen(normalized.scopes))
})

// --- The contract survives the route's own schema ---------------------------

test('a denial is not reshaped by the route schema or a host error handler', async () => {
  const app = Fastify()
  app.setErrorHandler((_error, _request, reply) => {
    reply.code(500).send({ rewritten: true })
  })
  app.register(agentPolicy, { identify: headerResolver })
  app.register(async (routes) => {
    routes.get(
      '/x',
      {
        config: { agent: { risk: 'write', scopes: ['orders:refund'] } },
        schema: { response: { 403: { type: 'object', properties: {} } } },
      },
      async () => ({ ok: true }),
    )
  })

  const response = await app.inject({
    method: 'GET',
    url: '/x',
    headers: { 'x-agent-id': 'https://bot.example' },
  })

  assert.equal(response.statusCode, 403)
  assert.equal(response.headers['content-type'], PROBLEM_CONTENT_TYPE)
  assert.deepEqual(response.json()['requiredScopes'], ['orders:refund'])
  await app.close()
})
