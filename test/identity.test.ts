import assert from 'node:assert/strict'
import test from 'node:test'

import Fastify, { type FastifyInstance, type FastifyRequest } from 'fastify'

import agentPolicy, { type AgentIdentity } from '../src/index.ts'

/** Resolves an identity from `x-agent-id`, and nothing otherwise. */
function headerResolver(request: FastifyRequest): AgentIdentity | null {
  const id = request.headers['x-agent-id']
  if (typeof id !== 'string' || id.length === 0) return null
  return { id, class: 'verified', scopes: ['orders:read'] }
}

async function buildApp(applyTo: 'agents' | 'all'): Promise<FastifyInstance> {
  const app = Fastify()
  await app.register(agentPolicy, { identify: headerResolver, applyTo })

  app.get('/policed', { config: { agent: { risk: 'read' } } }, async (request) => ({
    agent: request.agent,
  }))

  app.get('/open', async (request) => ({ agent: request.agent }))

  return app
}

test('agent identified: request.agent is the identity and the handler runs', async () => {
  const app = await buildApp('all')
  const response = await app.inject({
    method: 'GET',
    url: '/policed',
    headers: { 'x-agent-id': 'https://agent.example' },
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    agent: { id: 'https://agent.example', class: 'verified', scopes: ['orders:read'] },
  })
  await app.close()
})

test('human traffic: applyTo "agents" leaves an unidentified caller alone', async () => {
  const app = await buildApp('agents')
  const response = await app.inject({ method: 'GET', url: '/policed' })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), { agent: null })
  await app.close()
})

test('identity required: applyTo "all" denies an unidentified caller', async () => {
  const app = await buildApp('all')
  const response = await app.inject({ method: 'GET', url: '/policed' })

  assert.equal(response.statusCode, 401)
  assert.equal(response.headers['content-type'], 'application/problem+json')

  const body = response.json()
  assert.equal(body.type, 'https://github.com/umxr/fastify-agent-policy/problems/agent_identity_required')
  assert.equal(body.title, 'Agent identity required')
  assert.equal(body.status, 401)
  assert.equal(body.retryable, false)
  assert.equal(typeof body.detail, 'string')
  await app.close()
})

test('unpoliced route: identity still resolves and the response is unchanged', async () => {
  const app = await buildApp('all')

  const anonymous = await app.inject({ method: 'GET', url: '/open' })
  assert.equal(anonymous.statusCode, 200)
  assert.deepEqual(anonymous.json(), { agent: null })

  const identified = await app.inject({
    method: 'GET',
    url: '/open',
    headers: { 'x-agent-id': 'https://agent.example' },
  })
  assert.equal(identified.statusCode, 200)
  assert.equal(identified.json().agent.id, 'https://agent.example')
  await app.close()
})

test('request.agent is decorated on every request, policed or not', async () => {
  const app = Fastify()
  await app.register(agentPolicy, { identify: () => null })
  app.get('/', async (request) => ({ hasAgent: 'agent' in request, agent: request.agent }))

  const response = await app.inject({ method: 'GET', url: '/' })
  assert.deepEqual(response.json(), { hasAgent: true, agent: null })
  await app.close()
})

test('an async identify() resolver is awaited', async () => {
  const app = Fastify()
  await app.register(agentPolicy, {
    identify: async () => ({ id: 'https://slow.example' }),
    applyTo: 'all',
  })
  app.get('/', { config: { agent: { risk: 'read' } } }, async (request) => ({
    id: request.agent?.id,
  }))

  const response = await app.inject({ method: 'GET', url: '/' })
  assert.deepEqual(response.json(), { id: 'https://slow.example' })
  await app.close()
})

test('a resolver returning a malformed identity fails loudly', async () => {
  const app = Fastify()
  await app.register(agentPolicy, {
    identify: () => ({ id: 42 } as unknown as AgentIdentity),
  })
  app.get('/', async () => ({ ok: true }))

  const response = await app.inject({ method: 'GET', url: '/' })
  assert.equal(response.statusCode, 500)
  assert.equal(response.json().code, 'FST_AGENT_POLICY_INVALID_IDENTITY')
  await app.close()
})

test('hooks are hoisted, so routes in a nested plugin are policed too', async () => {
  const app = Fastify()
  app.register(agentPolicy, { identify: headerResolver, applyTo: 'all' })
  app.register(
    async (routes) => {
      routes.get('/nested', { config: { agent: { risk: 'read' } } }, async (request) => ({
        agent: request.agent,
      }))
    },
    { prefix: '/v1' },
  )
  await app.ready()

  const denied = await app.inject({ method: 'GET', url: '/v1/nested' })
  assert.equal(denied.statusCode, 401)
  assert.equal(denied.headers['content-type'], 'application/problem+json')

  const allowed = await app.inject({
    method: 'GET',
    url: '/v1/nested',
    headers: { 'x-agent-id': 'https://agent.example' },
  })
  assert.equal(allowed.statusCode, 200)
  assert.equal(allowed.json().agent.id, 'https://agent.example')

  await app.close()
})
