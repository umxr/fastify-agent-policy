import assert from 'node:assert/strict'
import test from 'node:test'

import Fastify, { type FastifyInstance } from 'fastify'

import agentPolicy, {
  type AgentPolicy,
  type AgentPolicyOptions,
  type MaxRiskAllowance,
} from '../src/index.ts'

const identify = () => null

/**
 * Builds an app the way a real one is laid out: the plugin is registered
 * first, then the routes arrive in their own plugin. Both are queued, so
 * route registration happens during boot and a bad policy surfaces as an
 * `app.ready()` rejection.
 */
async function readyError(build: (app: FastifyInstance) => void): Promise<Error> {
  const app = Fastify()
  app.register(agentPolicy, { identify })
  app.register(async (routes) => {
    build(routes)
  })

  try {
    await app.ready()
  } catch (error) {
    await app.close()
    return error as Error
  }
  await app.close()
  throw new assert.AssertionError({ message: 'expected app.ready() to reject' })
}

test('missing risk: app.ready() rejects and names the route', async () => {
  const error = await readyError((app) => {
    app.post('/orders/:id/refund', { config: { agent: {} } }, async () => ({ ok: true }))
  })

  assert.equal((error as Error & { code?: string }).code, 'FST_AGENT_POLICY_RISK_REQUIRED')
  assert.match(error.message, /POST \/orders\/:id\/refund/)
  assert.match(error.message, /"risk"/)
})

test('plugin defaults.risk satisfies a route that omits risk', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify, defaults: { risk: 'write' } })
  app.post('/orders', { config: { agent: {} } }, async () => ({ ok: true }))

  await app.ready()
  const response = await app.inject({ method: 'POST', url: '/orders' })
  assert.equal(response.statusCode, 200)
  await app.close()
})

test('unknown policy property: app.ready() rejects and names the property', async () => {
  const error = await readyError((app) => {
    app.get(
      '/reports',
      { config: { agent: { risk: 'read', budget: 10 } as unknown as AgentPolicy } },
      async () => ({ ok: true }),
    )
  })

  assert.equal((error as Error & { code?: string }).code, 'FST_AGENT_POLICY_INVALID_POLICY')
  assert.match(error.message, /GET \/reports/)
  assert.match(error.message, /unknown property "budget"/)
})

test('invalid risk value: app.ready() rejects and names the property', async () => {
  const error = await readyError((app) => {
    app.get(
      '/reports',
      { config: { agent: { risk: 'nuclear' } as unknown as AgentPolicy } },
      async () => ({ ok: true }),
    )
  })

  assert.match(error.message, /"risk" must be one of "read", "write", "destructive"/)
})

test('invalid dryRun, confirm, scopes and guard values all reject', async () => {
  const cases: Array<[unknown, RegExp]> = [
    [{ risk: 'read', dryRun: 'maybe' }, /"dryRun" must be one of/],
    [{ risk: 'read', confirm: true }, /"confirm" must be one of/],
    [{ risk: 'read', scopes: [] }, /"scopes" must be a non-empty array/],
    [{ risk: 'read', scopes: [1] }, /"scopes" must contain only non-empty strings/],
    [{ risk: 'read', scopes: { any: [], all: [] } }, /exactly one key/],
    [{ risk: 'read', scopes: { any: 'a' } }, /"scopes.any" must be a non-empty array/],
    [{ risk: 'read', guard: 'yes' }, /"guard" must be a function/],
    ['destructive', /config.agent must be an object/],
  ]

  for (const [policy, expected] of cases) {
    const error = await readyError((app) => {
      app.get('/x', { config: { agent: policy as AgentPolicy } }, async () => ({ ok: true }))
    })
    assert.match(error.message, expected)
  }
})

test('valid policy shapes register cleanly', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify })
  app.post(
    '/orders/:id/refund',
    {
      config: {
        agent: {
          risk: 'destructive',
          dryRun: 'handler',
          confirm: 'two-phase',
          scopes: { any: ['orders:refund', 'orders:admin'] },
          guard: (_request, agent) => agent.id.startsWith('https://'),
        },
      },
    },
    async () => ({ ok: true }),
  )
  await app.ready()
  await app.close()
})

test('GET route: the policy is validated exactly once despite two onRoute calls', async () => {
  // Fastify adds a HEAD route for every GET, and both `onRoute` invocations
  // share one `config` object. `validatePolicyShape` calls `Object.keys` on
  // the policy exactly once per validation, so the `ownKeys` trap counts them.
  let validations = 0
  const policy = new Proxy(
    { risk: 'read' },
    {
      ownKeys(target) {
        validations += 1
        return Reflect.ownKeys(target)
      },
    },
  ) as AgentPolicy

  const app = Fastify()
  await app.register(agentPolicy, { identify })
  app.get('/reports', { config: { agent: policy } }, async () => ({ ok: true }))
  await app.ready()

  assert.equal(validations, 1)

  const get = await app.inject({ method: 'GET', url: '/reports' })
  assert.equal(get.statusCode, 200)
  const head = await app.inject({ method: 'HEAD', url: '/reports' })
  assert.equal(head.statusCode, 200)
  assert.equal(validations, 1)

  await app.close()
})

test('Fastify-injected url and method config keys are tolerated', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify })
  app.get('/reports', { config: { agent: { risk: 'read' } } }, async (request) => ({
    // Fastify injects these two into `routeOptions.config`.
    url: request.routeOptions.config.url,
    method: request.routeOptions.config.method,
  }))
  await app.ready()

  const response = await app.inject({ method: 'GET', url: '/reports' })
  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { url: '/reports', method: 'GET' })
  await app.close()
})

test('invalid plugin options reject at registration', async () => {
  // Deliberately malformed, so the values cannot satisfy `AgentPolicyOptions`.
  // Each case is still typed as an options-shaped object: `as never` would
  // erase the argument type entirely and hide a case that stopped meaning
  // what it says.
  type MalformedOptions = Partial<Record<keyof AgentPolicyOptions, unknown>>
  const cases: Array<[MalformedOptions, RegExp]> = [
    [{}, /"identify" is required/],
    [{ identify, applyTo: 'humans' }, /"applyTo" must be/],
    [{ identify, problemBaseUri: '' }, /"problemBaseUri" must be/],
    [{ identify, defaults: { risk: 'nuclear' } }, /"defaults" -- "risk" must be one of/],
    [{ identify, defaults: { nope: 1 } }, /"defaults" -- unknown property "nope"/],
    [{ identify, maxRisk: { verified: 'nuclear' } }, /"maxRisk.verified" must be one of/],
    [{ identify, maxRisk: { trusted: 'write', default: true } }, /"maxRisk.default" must be one of/],
    [{ identify, maxRisk: 'write' }, /"maxRisk" must be an object/],
    [{ identify, maxRisk: ['write'] }, /"maxRisk" must be an object/],
    [{ identify, maxRisk: null }, /"maxRisk" must be an object/],
    [{ identify, maxRisk: { '': 'write' } }, /"maxRisk" keys must be non-empty/],
    // An empty map matches no class and has no `default`, so it denies every
    // agent on every policed route while reading as "nothing configured".
    [{ identify, maxRisk: {} }, /"maxRisk" must name at least one agent class/],
  ]

  for (const [options, expected] of cases) {
    const app = Fastify()
    await assert.rejects(
      async () => {
        await app.register(agentPolicy, options as unknown as AgentPolicyOptions)
        await app.ready()
      },
      (error: Error) => {
        assert.match(error.message, expected)
        return true
      },
    )
    await app.close()
  }
})

test('a non-empty maxRisk map registers and takes effect at request time', async () => {
  const maxRisk: MaxRiskAllowance = { trusted: 'destructive', verified: 'write', default: 'read' }

  const app = Fastify()
  await app.register(agentPolicy, {
    identify: (request) => ({
      id: 'https://agent.example',
      class: String(request.headers['x-agent-class'] ?? 'verified'),
    }),
    maxRisk,
  })
  app.get('/reports', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
  app.delete('/reports', { config: { agent: { risk: 'destructive' } } }, async () => ({ ok: true }))
  await app.ready()

  const read = await app.inject({ method: 'GET', url: '/reports' })
  assert.equal(read.statusCode, 200, 'a read is within the verified allowance')

  const destructive = await app.inject({ method: 'DELETE', url: '/reports' })
  assert.equal(destructive.statusCode, 403, 'a destructive route is not')
  assert.equal(
    destructive.json().type,
    'https://github.com/umxr/fastify-agent-policy/problems/risk_tier_blocked',
  )

  const trusted = await app.inject({
    method: 'DELETE',
    url: '/reports',
    headers: { 'x-agent-class': 'trusted' },
  })
  assert.equal(trusted.statusCode, 200, 'trusted may call anything')

  await app.close()
})

test('maxRisk is optional: omitting it skips the tier check', async () => {
  const app = Fastify()
  await app.register(agentPolicy, {
    identify: () => ({ id: 'https://agent.example', class: 'nothing-configured' }),
  })
  app.delete('/reports', { config: { agent: { risk: 'destructive' } } }, async () => ({ ok: true }))
  await app.ready()

  assert.equal((await app.inject({ method: 'DELETE', url: '/reports' })).statusCode, 200)
  await app.close()
})

test('a route without config.agent is never validated', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify })
  app.get('/open', { config: { cacheTtl: 30 } }, async () => ({ ok: true }))
  await app.ready()

  const response = await app.inject({ method: 'GET', url: '/open' })
  assert.equal(response.statusCode, 200)
  await app.close()
})
