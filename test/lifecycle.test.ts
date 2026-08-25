import assert from 'node:assert/strict'
import test from 'node:test'

import Fastify, { type FastifyInstance } from 'fastify'

import agentPolicy, { PROBLEM_CONTENT_TYPE } from '../src/index.ts'

const identify = () => null

/** Collects everything the app logs, as parsed pino records. */
function captureLogs(): { records: Array<Record<string, unknown>>; stream: { write(line: string): void } } {
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

async function rejectionOf(app: FastifyInstance): Promise<Error> {
  try {
    await app.ready()
  } catch (error) {
    await app.close()
    return error as Error
  }
  await app.close()
  throw new assert.AssertionError({ message: 'expected app.ready() to reject' })
}

test('route before plugin: app.ready() rejects and names the route', async () => {
  const app = Fastify()
  // Registered before the plugin, so `onRoute` never validated this policy.
  // Without the sweep the route looks policed, has `request.agent`, and is
  // never denied.
  app.get('/early', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
  app.register(agentPolicy, { identify, applyTo: 'all' })

  const error = await rejectionOf(app)
  assert.equal(
    (error as Error & { code?: string }).code,
    'FST_AGENT_POLICY_ROUTES_BEFORE_PLUGIN',
  )
  assert.match(error.message, /early/)
  assert.match(error.message, /Register the plugin before any route/)
})

test('a route with a malformed policy registered before the plugin still fails boot', async () => {
  const app = Fastify()
  // `risk: 'nuclear'` would be caught by `onRoute` -- but `onRoute` never
  // runs for this route, so only the sweep can catch it.
  app.get('/early', { config: { agent: { risk: 'nuclear' } } } as never, async () => ({ ok: true }))
  app.register(agentPolicy, { identify })

  const error = await rejectionOf(app)
  assert.equal(
    (error as Error & { code?: string }).code,
    'FST_AGENT_POLICY_ROUTES_BEFORE_PLUGIN',
  )
})

test('plugin registered first: the sweep stays quiet', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify })
  app.get('/late', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))

  await app.ready()
  assert.equal((await app.inject({ method: 'GET', url: '/late' })).statusCode, 200)
  await app.close()
})

test('double registration on the same instance rejects', async () => {
  const app = Fastify()
  app.register(agentPolicy, { identify, problemBaseUri: 'https://a.example/p' })
  app.register(agentPolicy, { identify, problemBaseUri: 'https://b.example/p' })

  const error = await rejectionOf(app)
  assert.equal(
    (error as Error & { code?: string }).code,
    'FST_AGENT_POLICY_DUPLICATE_REGISTRATION',
  )
  assert.match(error.message, /already registered/)
})

test('encapsulated sibling scopes each get their own registration', async () => {
  const app = Fastify()

  app.register(async (scope) => {
    await scope.register(agentPolicy, {
      identify: () => null,
      applyTo: 'all',
      problemBaseUri: 'https://left.example/p',
    })
    scope.get('/left', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
  })

  app.register(async (scope) => {
    await scope.register(agentPolicy, {
      identify: () => ({ id: 'https://agent.example' }),
      applyTo: 'all',
      problemBaseUri: 'https://right.example/p',
    })
    scope.get('/right', { config: { agent: { risk: 'read' } } }, async (request) => ({
      agent: request.agent,
    }))
  })

  await app.ready()

  // Each scope keeps its own resolver and its own problem base URI.
  const left = await app.inject({ method: 'GET', url: '/left' })
  assert.equal(left.statusCode, 401)
  assert.equal(left.json().type, 'https://left.example/p/agent_identity_required')

  const right = await app.inject({ method: 'GET', url: '/right' })
  assert.equal(right.statusCode, 200)
  assert.equal(right.json().agent.id, 'https://agent.example')

  await app.close()
})

test('nested registration rejects: an enclosing scope already has the plugin', async () => {
  const app = Fastify()
  app.register(agentPolicy, { identify })
  app.register(async (child) => {
    // `fastify-plugin` skips encapsulation, so this would join the root's
    // hooks rather than replace them.
    await child.register(agentPolicy, { identify, defaults: { risk: 'read' } })
    child.get('/child', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
  })

  const error = await rejectionOf(app)
  assert.equal(
    (error as Error & { code?: string }).code,
    'FST_AGENT_POLICY_NESTED_REGISTRATION',
  )
  assert.match(error.message, /already registered on an enclosing/)
})

test('nesting is rejected rather than running a side-effecting guard twice', async () => {
  // The measured failure this rule exists for: with both registrations live,
  // the guard ran twice per request, so the documented spend-counter example
  // double-charged. Boot must stop before a request can prove it.
  let guardRuns = 0
  const app = Fastify()
  app.register(agentPolicy, { identify: () => ({ id: 'https://agent.example' }) })
  app.register(async (child) => {
    await child.register(agentPolicy, { identify: () => ({ id: 'https://agent.example' }) })
    child.get(
      '/spend',
      {
        config: {
          agent: {
            risk: 'write',
            guard: () => {
              guardRuns += 1
              return true
            },
          },
        },
      },
      async () => ({ ok: true }),
    )
  })

  await rejectionOf(app)
  assert.equal(guardRuns, 0, 'no request was ever served')
})

test('a deeply nested registration is rejected too', async () => {
  const app = Fastify()
  app.register(agentPolicy, { identify })
  app.register(async (middle) => {
    await middle.register(async (inner) => {
      await inner.register(agentPolicy, { identify })
    })
  })

  const error = await rejectionOf(app)
  assert.equal(
    (error as Error & { code?: string }).code,
    'FST_AGENT_POLICY_NESTED_REGISTRATION',
  )
})

test('problemBaseUri must parse as a URI', async () => {
  for (const bad of ['not a uri', '/problems', '', '  ']) {
    const app = Fastify()
    app.register(agentPolicy, { identify, problemBaseUri: bad })
    const error = await rejectionOf(app)
    assert.equal(
      (error as Error & { code?: string }).code,
      'FST_AGENT_POLICY_INVALID_OPTIONS',
      `expected ${JSON.stringify(bad)} to be rejected`,
    )
    assert.match(error.message, /"problemBaseUri" must be a valid URI/)
  }
})

test('a valid non-http problemBaseUri is accepted', async () => {
  const app = Fastify()
  await app.register(agentPolicy, {
    identify,
    applyTo: 'all',
    problemBaseUri: 'urn:example:agent-policy',
  })
  app.get('/x', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))

  const response = await app.inject({ method: 'GET', url: '/x' })
  assert.equal(response.json().type, 'urn:example:agent-policy/agent_identity_required')
  await app.close()
})

test('a 401 denial carries a WWW-Authenticate challenge', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify, applyTo: 'all' })
  app.get('/x', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))

  const response = await app.inject({ method: 'GET', url: '/x' })
  assert.equal(response.statusCode, 401)
  // RFC 9110 section 11.6.1 makes the header mandatory on a 401.
  assert.equal(response.headers['www-authenticate'], 'Bearer realm="agent-policy"')
  await app.close()
})

test('the WWW-Authenticate challenge is configurable', async () => {
  const app = Fastify()
  await app.register(agentPolicy, {
    identify,
    applyTo: 'all',
    wwwAuthenticate: 'Signature realm="bots"',
  })
  app.get('/x', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))

  const response = await app.inject({ method: 'GET', url: '/x' })
  assert.equal(response.headers['www-authenticate'], 'Signature realm="bots"')
  await app.close()
})

test('denials are logged with the agent, the route and the reason', async () => {
  const { records, stream } = captureLogs()
  const app = Fastify({ logger: { level: 'trace', stream } })
  await app.register(agentPolicy, { identify, applyTo: 'all' })
  app.get('/orders', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))

  await app.inject({ method: 'GET', url: '/orders' })

  const denial = records.find(
    (record) => (record['agentPolicy'] as Record<string, unknown> | undefined)?.['decision'] === 'denied',
  )
  assert.ok(denial, 'a denial was logged')
  assert.deepEqual(denial['agentPolicy'], {
    decision: 'denied',
    problem: 'agent_identity_required',
    reason: 'no agent identity resolved',
    retryable: false,
    agent: null,
    method: 'GET',
    url: '/orders',
  })
  await app.close()
})

test('a resolver that rejects denies with retryable: true and never leaks its message', async () => {
  const { records, stream } = captureLogs()
  const app = Fastify({ logger: { level: 'trace', stream } })
  await app.register(agentPolicy, {
    identify: async () => {
      throw new Error('redis://secret-host:6379 refused the connection')
    },
    applyTo: 'all',
  })
  app.get('/x', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))

  const response = await app.inject({ method: 'GET', url: '/x' })

  assert.equal(response.statusCode, 401)
  assert.equal(response.headers['content-type'], PROBLEM_CONTENT_TYPE)
  const body = response.json()
  assert.equal(body.retryable, true)
  assert.ok(!response.body.includes('secret-host'), 'the resolver message never reaches the caller')

  // It goes to the log instead.
  const logged = records.find((record) => record['level'] === 50)
  assert.ok(logged, 'the failure was logged at error level')
  assert.match(
    JSON.stringify((logged['err'] as Record<string, unknown>)?.['message']),
    /secret-host/,
  )
  await app.close()
})

test('a rejecting resolver does not take an unpoliced route down with it', async () => {
  const { records, stream } = captureLogs()
  const app = Fastify({ logger: { level: 'trace', stream } })
  let handlerRuns = 0

  await app.register(agentPolicy, {
    identify: () => {
      throw new Error('boom')
    },
    applyTo: 'all',
  })
  // No `config.agent`: this route never asked for a policy, so a failure in
  // the policy subsystem must not deny it.
  app.get('/open', async (request) => {
    handlerRuns += 1
    return { ok: true, agent: request.agent }
  })

  const response = await app.inject({ method: 'GET', url: '/open' })

  assert.equal(response.statusCode, 200)
  assert.equal(handlerRuns, 1, 'the handler ran')
  assert.deepEqual(response.json(), { ok: true, agent: null })

  // The failure is still logged, and no denial was.
  assert.ok(
    records.some((record) => record['level'] === 50),
    'the resolver failure was logged at error level',
  )
  assert.ok(
    !records.some(
      (record) =>
        (record['agentPolicy'] as Record<string, unknown> | undefined)?.['decision'] === 'denied',
    ),
    'nothing was denied',
  )
  await app.close()
})

test('a rejecting resolver still fails a policed route closed', async () => {
  const app = Fastify()
  let handlerRuns = 0

  await app.register(agentPolicy, {
    identify: () => {
      throw new Error('boom')
    },
    // Even under 'agents': the policy cannot be honoured without an identity.
    applyTo: 'agents',
  })
  app.get('/policed', { config: { agent: { risk: 'read' } } }, async () => {
    handlerRuns += 1
    return { ok: true }
  })

  const response = await app.inject({ method: 'GET', url: '/policed' })
  assert.equal(response.statusCode, 401)
  assert.equal(response.json().retryable, true)
  assert.equal(handlerRuns, 0, 'the handler never ran')
  assert.ok(!response.body.includes('boom'))
  await app.close()
})

test("registrationOrder 'warn' boots and logs a warning naming the routes", async () => {
  const { records, stream } = captureLogs()
  const app = Fastify({ logger: { level: 'trace', stream } })

  app.get('/health', async () => ({ ok: true }))
  app.get('/early', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
  app.register(agentPolicy, { identify, applyTo: 'all', registrationOrder: 'warn' })

  await app.ready()

  const warning = records.find(
    (record) =>
      (record['agentPolicy'] as Record<string, unknown> | undefined)?.['registrationOrder'] ===
      'warn',
  )
  assert.ok(warning, 'a warning was logged')
  assert.equal(warning['level'], 40)
  assert.match(String(warning['msg']), /health/)
  assert.match(String(warning['msg']), /early/)
  assert.match(String(warning['msg']), /never validated and can never be enforced/)

  // Booting is the whole point of 'warn' -- and the hole it reopens is real:
  // the pre-plugin route declares a policy and is still never denied.
  assert.equal((await app.inject({ method: 'GET', url: '/health' })).statusCode, 200)
  assert.equal((await app.inject({ method: 'GET', url: '/early' })).statusCode, 200)
  await app.close()
})

test("registrationOrder 'off' boots with no warning at all", async () => {
  const { records, stream } = captureLogs()
  const app = Fastify({ logger: { level: 'trace', stream } })

  app.get('/early', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
  app.register(agentPolicy, { identify, applyTo: 'all', registrationOrder: 'off' })

  await app.ready()

  assert.ok(
    !records.some(
      (record) => (record['agentPolicy'] as Record<string, unknown> | undefined)?.[
        'registrationOrder'
      ] !== undefined,
    ),
    'the sweep was skipped entirely',
  )
  assert.equal((await app.inject({ method: 'GET', url: '/early' })).statusCode, 200)
  await app.close()
})

test("registrationOrder defaults to 'strict'", async () => {
  const app = Fastify()
  app.get('/early', async () => ({ ok: true }))
  app.register(agentPolicy, { identify })

  const error = await rejectionOf(app)
  assert.equal(
    (error as Error & { code?: string }).code,
    'FST_AGENT_POLICY_ROUTES_BEFORE_PLUGIN',
  )
})

test("registrationOrder 'strict' is explicit and still throws", async () => {
  const app = Fastify()
  app.get('/early', async () => ({ ok: true }))
  app.register(agentPolicy, { identify, registrationOrder: 'strict' })

  const error = await rejectionOf(app)
  assert.equal(
    (error as Error & { code?: string }).code,
    'FST_AGENT_POLICY_ROUTES_BEFORE_PLUGIN',
  )
})

test('an unknown registrationOrder value rejects at registration', async () => {
  const app = Fastify()
  app.register(agentPolicy, { identify, registrationOrder: 'lenient' as never })

  const error = await rejectionOf(app)
  assert.equal((error as Error & { code?: string }).code, 'FST_AGENT_POLICY_INVALID_OPTIONS')
  assert.match(error.message, /"registrationOrder" must be "strict", "warn" or "off"/)
})

test("'warn' and 'off' stay quiet when nothing was registered early", async () => {
  for (const registrationOrder of ['warn', 'off'] as const) {
    const { records, stream } = captureLogs()
    const app = Fastify({ logger: { level: 'trace', stream } })
    await app.register(agentPolicy, { identify, applyTo: 'all', registrationOrder })
    app.get('/late', { config: { agent: { risk: 'read' } } }, async () => ({ ok: true }))
    await app.ready()

    assert.ok(
      !records.some((record) => record['level'] === 40),
      `${registrationOrder}: nothing to warn about`,
    )
    // The route registered after the plugin is policed as normal.
    assert.equal((await app.inject({ method: 'GET', url: '/late' })).statusCode, 401)
    await app.close()
  }
})
