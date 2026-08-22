# fastify-agent-policy

Declare what an AI agent caller is allowed to do on a Fastify route, and deny
it with an answer the agent can act on.

`fastify-web-bot-auth` answers *who is this*. This plugin answers *what is it
allowed to do*.

> **Status.** This release ships the foundation: identity resolution, route
> policy declaration with fail-fast validation, and the full RFC 9457 error
> contract. Scope, risk-tier and guard enforcement, dry-run and two-phase
> confirmation are declared and validated now, and enforced in follow-up
> releases. See [What is enforced today](#what-is-enforced-today).

- Node 20+, Fastify v5, ESM and CJS.
- Two runtime dependencies: `fastify-plugin` and `@fastify/error`.

```sh
npm install fastify-agent-policy
```

## The error contract

Errors are the product. An agent that gets a bare `403` has nothing to act on;
an agent that gets a problem document knows what to do next. Every denial is
`application/problem+json` ([RFC 9457][rfc9457]) with a stable `type` URI.

```http
HTTP/1.1 401 Unauthorized
content-type: application/problem+json
www-authenticate: Bearer realm="agent-policy"

{
  "type": "https://github.com/umxr/fastify-agent-policy/problems/agent_identity_required",
  "title": "Agent identity required",
  "status": 401,
  "detail": "This route requires an identified agent caller. ...",
  "retryable": false
}
```

All eight types are defined and frozen from this first release. Adding one
later would change a published contract, so none is added later.

| `type` slug | Status | Meaning | Extensions |
|---|---|---|---|
| `agent_identity_required` | 401 | The route is policed and the caller could not be identified. | `retryable` |
| `scope_denied` | 403 | The agent does not hold the scopes the route requires. | `requiredScopes`, `retryable` |
| `risk_tier_blocked` | 403 | The route's risk tier is above what this agent class may call. | `retryable` |
| `guard_failed` | 403 | The route's custom guard refused the call. | `retryable` |
| `confirmation_required` | 409 | The call needs a second, confirmed request. | `confirmationToken`, `expiresIn`, `retryable` |
| `confirmation_invalid` | 409 | The confirmation token does not match this request. | `retryable` |
| `confirmation_expired` | 409 | The confirmation token timed out. | `retryable` |
| `dry_run_unsupported` | 400 | The caller asked for a dry run the route does not offer. | `retryable` |

`type` is always present. RFC 9457 makes every member optional and treats an
absent `type` as `about:blank`, which carries no meaning, so this plugin always
emits `type`, `title` and `status`.

The base URI identifies the problem type. It does not have to resolve, but it
must parse as a URI -- a value `new URL()` rejects fails at registration rather
than shipping in the contract. Point it at your own docs with `problemBaseUri`:

```ts
await app.register(agentPolicy, {
  identify: webBotAuth(),
  problemBaseUri: 'https://api.example/problems',
})
// -> "type": "https://api.example/problems/scope_denied"
```

### What keeps the contract intact

Three things, each of which was empirically load-bearing:

- **Denials are sent, never thrown.** A thrown error goes through the host
  application's root `setErrorHandler`, which rewrites the body and the content
  type. This plugin never calls `setErrorHandler` and never throws a denial.
- **A reply serializer is installed before sending.** A route that declares
  `schema.response[401]` otherwise serializes the denial through its own schema
  and strips it to `{}` -- while the content type still claims
  `application/problem+json`. Your route's schemas still apply to every
  response the plugin did not write.
- **Denials run in `onRequest`**, the first hook in the lifecycle, so a denial
  precedes body parsing and schema validation. In `preHandler` an unidentified
  caller with a malformed body received Fastify's `400 FST_ERR_VALIDATION` in
  `application/json` instead of the problem document.

The content type is exactly `application/problem+json`, with no `charset`
parameter -- RFC 9457 registers none, and JSON is UTF-8 by definition. Compare
against the exported `PROBLEM_CONTENT_TYPE` rather than a literal.

Every denial is logged through `request.log.warn` under an `agentPolicy` key
carrying the decision, the problem type, the reason, the agent id, and the
route, so an operator can see who was denied and why.

## Usage

```ts
import Fastify from 'fastify'
import agentPolicy, { webBotAuth } from 'fastify-agent-policy'

const app = Fastify()

await app.register(agentPolicy, {
  identify: webBotAuth(),      // pluggable; see Resolvers
  applyTo: 'agents',           // 'agents' (default) | 'all'
  defaults: { risk: 'write' }, // inherited by every route policy
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
        guard: (request, agent) => agent.class === 'trusted',
      },
    },
  },
  async (request) => {
    // `request.agent` is `AgentIdentity | null` on every request.
    return { refunded: true, by: request.agent?.id ?? 'human' }
  },
)
```

CommonJS:

```js
const agentPolicy = require('fastify-agent-policy').default
const { webBotAuth } = require('fastify-agent-policy')
```

### Registration order

**Register the plugin before your routes**, and before any hook that reads
`request.agent`.

`onRoute` only fires for routes registered after the plugin loads. A route
registered earlier is never validated and can never be denied -- yet it still
gets `request.agent`, so it looks policed and is not. That state is what this
plugin exists to prevent, so it fails the boot instead:

```
FST_AGENT_POLICY_ROUTES_BEFORE_PLUGIN: fastify-agent-policy was registered
after these routes, so their agent policy was never validated and can never
be enforced. Register the plugin before any route:
└── /early (GET, HEAD)
```

Two consequences worth knowing:

- The check fires for *any* route registered before the plugin, not only ones
  declaring `config.agent`. Fastify exposes no way to read a route's `config`
  at boot, so the plugin cannot narrow it further. A plain
  `app.get('/health')` declared before the plugin fails the boot too.
- It runs for the first registration in an application only. The router is
  shared across every encapsulated scope, so a sibling scope's routes are not
  attributable to yours.

The usual fix is to move the registration above your routes. When you cannot,
`registrationOrder` relaxes the check:

| Value | Behaviour |
|---|---|
| `'strict'` (default) | Fails the boot with `FST_AGENT_POLICY_ROUTES_BEFORE_PLUGIN`. |
| `'warn'` | Logs a warning naming the routes and boots. |
| `'off'` | Skips the check. |

**Be clear about what you are buying.** `'warn'` and `'off'` reopen exactly the
hole `'strict'` closes. A route that declares `config.agent` before the plugin
loads still gets `request.agent`, so it looks policed in your handler -- and it
is never validated and never denied, silently, for as long as it exists. A
malformed `risk` on such a route is not caught either. Prefer moving the
registration; reach for `'warn'` only while you do, and for `'off'` only when
you have another reason to be certain no pre-plugin route declares a policy.

```ts
await app.register(agentPolicy, {
  identify: webBotAuth(),
  registrationOrder: 'warn', // boots, but the routes above stay unpoliced
})
```

`request.agent` is assigned in an `onRequest` hook added when the plugin loads.
Fastify runs hooks in registration order, so **a hook registered before the
plugin sees `request.agent === null`**, whatever the caller sent. Register the
plugin first, or read the agent from `preHandler` or later.

### Registering more than once

A second registration on the same instance is rejected with
`FST_AGENT_POLICY_DUPLICATE_REGISTRATION`. It would run `identify()` twice per
request and silently discard its own `problemBaseUri`.

Separate encapsulated scopes are fine, and each keeps its own resolver, base
URI and challenge:

```ts
app.register(async (partners) => {
  await partners.register(agentPolicy, { identify: webBotAuth(), applyTo: 'all' })
  partners.get('/partners/orders', { config: { agent: { risk: 'read' } } }, handler)
})

app.register(async (internal) => {
  await internal.register(agentPolicy, { identify: bearerClaims(toIdentity) })
  internal.get('/internal/orders', { config: { agent: { risk: 'read' } } }, handler)
})
```

## Plugin options

| Option | Type | Default | Notes |
|---|---|---|---|
| `identify` | `(request) => AgentIdentity \| null \| Promise<...>` | *required* | There is no default identity scheme. Guessing one is how policy ends up attached to a spoofable header. |
| `applyTo` | `'agents' \| 'all'` | `'agents'` | `'all'` denies unidentified callers on policed routes with `agent_identity_required`. |
| `defaults` | `AgentPolicy` | `{}` | Merged underneath every route policy. |
| `problemBaseUri` | `string` | `https://github.com/umxr/fastify-agent-policy/problems` | Base for the `type` URIs. Must parse as a URI. |
| `wwwAuthenticate` | `string` | `Bearer realm="agent-policy"` | The challenge sent with a 401, which RFC 9110 makes mandatory. Set it to match what your resolver reads. |
| `registrationOrder` | `'strict' \| 'warn' \| 'off'` | `'strict'` | What to do about routes registered before the plugin. See [Registration order](#registration-order). |

## Route policy

Declared under `config.agent`, and validated when the route registers.

| Property | Type | Notes |
|---|---|---|
| `risk` | `'read' \| 'write' \| 'destructive'` | Required, here or in `defaults.risk`. |
| `scopes` | `string[] \| { any: string[] } \| { all: string[] }` | A bare array means all of them. |
| `dryRun` | `false \| 'preview' \| 'handler'` | |
| `confirm` | `false \| 'two-phase'` | |
| `guard` | `(request, agent) => boolean \| { allow, reason }` | May be async. |

### Risk is declared, never guessed

`risk` is never inferred from the HTTP method. `POST /reports/search` is a read
and `GET /jobs/:id/cancel` is not, so the method tells you nothing worth
betting a refund on. A route with `config.agent` and no `risk` -- from the
route or from `defaults` -- fails at boot:

```
FST_AGENT_POLICY_RISK_REQUIRED: Invalid agent policy on route
POST /orders/:id/refund: "risk" is required and plugin option
"defaults.risk" is not set
```

### Failing fast

Every policy problem is a coded error thrown while the route registers, so it
surfaces from `app.ready()` and never from a request.

| Code | Cause |
|---|---|
| `FST_AGENT_POLICY_INVALID_OPTIONS` | The plugin options or `defaults` are malformed, including a `problemBaseUri` that is not a URI. |
| `FST_AGENT_POLICY_INVALID_POLICY` | A route's `config.agent` is malformed. The message names the route and the property. |
| `FST_AGENT_POLICY_RISK_REQUIRED` | No `risk` from the route or the defaults. |
| `FST_AGENT_POLICY_ROUTES_BEFORE_PLUGIN` | Routes were registered before the plugin, so their policy can never be enforced. |
| `FST_AGENT_POLICY_DUPLICATE_REGISTRATION` | The plugin was registered twice on one instance. |
| `FST_AGENT_POLICY_UNKNOWN_PROBLEM` | `sendProblem`/`buildProblem` was asked for a type that does not exist. |
| `FST_AGENT_POLICY_INVALID_IDENTITY` | An `identify()` resolver returned something that is not an identity. Request time, not boot. |

## Resolvers

An identity is `{ id, scopes?, class?, meta? }`. `id` must be stable for the
same caller: later releases bind confirmation tokens to it.

### `webBotAuth(options?)`

Reads the verdict `fastify-web-bot-auth` leaves on the request. This plugin
never dereferences a signature agent URL, fetches a key directory or verifies
an HTTP message signature -- that is the other plugin's job.

- `verified !== true` produces `null`. No proof, no identity.
- `trusted === true` produces `class: 'trusted'`; anything else `'verified'`.
  `trusted` is `undefined` whenever `verified` is `false`, so it is never read
  as "falsy means denied".
- `id` is the normalized https origin of the signature agent. A non-https
  agent produces `null`.

```ts
identify: webBotAuth({ property: 'webBotAuth', scopes: ['crawl:read'] })
```

### `signatureAgent(options?)`

Reads the `Signature-Agent` header, in both the RFC 8941 Dictionary form
(`sig="https://agent.example"`) and the legacy bare quoted-string form
(`"https://agent.example"`). Parameters (`;expires=…`) are dropped, and a
semicolon inside the quoted value is preserved rather than truncating it.

When the header arrives more than once, every value is parsed and they must
agree. A second header can neither override the first nor be silently ignored:
disagreement produces no identity at all.

Nothing is verified, so the identity is always `class: 'unverified'`. The Web
Bot Auth draft forbids attaching policy to an unverified signature agent. Use
this for telemetry, or behind your own trust decision -- not as the gate on a
destructive route.

### `bearerClaims(mapFn, options?)`

Maps token claims another plugin has already verified.

```ts
identify: bearerClaims<{ sub: string; scope?: string }>((claims) => ({
  id: claims.sub,
  scopes: claims.scope?.split(' '),
  class: 'verified',
}))
```

Claims are read from `request.user` by default, which is where `@fastify/jwt`
puts them after `jwtVerify()`. Change it with `{ claimsProperty }`. This plugin
never parses or verifies a bearer token itself: decoding a JWT payload without
checking its signature turns an attacker-supplied string into a policy
identity.

### `userAgentPattern(patterns, options?)`

Matches the `User-Agent` header. The `id` is the first capture group, or the
whole match when the pattern has none. Always `class: 'unverified'` -- anyone
can send a User-Agent.

```ts
identify: userAgentPattern([/^(MyAgent)\/[\d.]+$/, /GPTBot/])
```

### Your own

`identify` is any function returning `AgentIdentity | null`, sync or async.
Return `null` for human traffic.

If it **throws or rejects**, the error goes to `request.log.error` and never
reaches the caller -- a resolver message can name internal hosts or carry a
token. What happens next depends on the route:

- **A route that declares `config.agent` fails closed.** Its policy cannot be
  honoured without an identity, so the request is denied with
  `agent_identity_required` and `retryable: true`. This holds under
  `applyTo: 'agents'` too.
- **A route that declares no policy is left alone.** It never asked for policy,
  so a failure in the policy subsystem does not take it down. `request.agent`
  is `null` and the handler runs.

Returning a malformed identity is a different mistake: that is a programming
error, and it surfaces as `FST_AGENT_POLICY_INVALID_IDENTITY`.

## What is enforced today

| Requirement | Declared | Validated at boot | Enforced at request time |
|---|---|---|---|
| FR1 identity, `request.agent` | yes | n/a | yes |
| FR2 route policy | yes | yes -- shape, and `risk` resolution | shape only; nothing is denied on the basis of the policy's contents |
| FR8 error contract | yes | yes | yes, for `agent_identity_required` |
| FR3 scopes | yes | yes | not yet |
| FR4 risk tiers | yes | yes | not yet |
| FR5 dry-run | yes | yes | not yet |
| FR6 confirmation | yes | yes | not yet |
| FR7 guards | yes | yes | not yet |

Declaring a policy today means it is checked for shape today, and starts being
enforced when you upgrade. Nothing in the config block changes shape.

## Public API

Everything is exported from the package root; there are no deep imports.

### Plugin

| Export | What it is |
|---|---|
| `default`, `agentPolicy` | The plugin. |

### Resolvers

| Export | What it is |
|---|---|
| `webBotAuth`, `signatureAgent`, `bearerClaims`, `userAgentPattern` | The four built-in resolvers. |
| `parseSignatureAgent(value, key?)` | Parses one `Signature-Agent` header value and returns the raw agent string, or `null`. Exposed so you can reuse the parser in your own resolver. |
| `normalizeAgentOrigin(value)` | Normalizes an agent URL to its https origin, or `null` for anything that is not https. Use it to keep your own resolver's `id` values consistent with the built-ins. |

### Error contract

| Export | What it is |
|---|---|
| `sendProblem(reply, kind, extensions?)` | Sends a denial and returns the reply. |
| `buildProblem(kind, extensions?, baseUri?)` | Builds the document without sending it. |
| `PROBLEM_TYPES` | Frozen map of all eight types to `{ slug, status, title }`. Drive your own tests or docs off this rather than hardcoding slugs. |
| `PROBLEM_CONTENT_TYPE` | `'application/problem+json'`. |
| `DEFAULT_PROBLEM_BASE_URI` | The base URI used when `problemBaseUri` is not set. |
| `DEFAULT_WWW_AUTHENTICATE` | The challenge used when `wwwAuthenticate` is not set. |
| `isValidProblemBaseUri(value)` | The `new URL()` check the plugin runs at registration. |

### Errors and validation

| Export | What it is |
|---|---|
| `InvalidAgentPolicyError`, `MissingRiskTierError`, `InvalidAgentPolicyOptionsError`, `RoutesBeforePluginError`, `DuplicateRegistrationError`, `UnknownProblemKindError`, `InvalidAgentIdentityError` | The coded error classes, for `instanceof` checks in your own boot tests. |
| `validatePolicy(routeName, policy, defaults?)` | The registration-time validator, returning the merged policy with `risk` resolved. Useful if you build route options programmatically and want to fail before Fastify sees them. |

### Types

`AgentIdentity`, `AgentIdentityResolver`, `SyncAgentIdentityResolver`,
`AgentPolicy`, `AgentPolicyDefaults`, `ResolvedAgentPolicy`,
`AgentPolicyOptions`, `ApplyTo`, `RegistrationOrder`, `RiskTier`,
`ScopeRequirement`, `DryRunMode`,
`ConfirmMode`, `AgentGuard`, `GuardResult`, `ProblemKind`, `ProblemDocument`,
`ProblemDefinition`, `ProblemExtensions`, `WebBotAuthResult`, and the option
types for each resolver.

Registering the plugin also augments Fastify: `request.agent` is
`AgentIdentity | null`, and `config.agent` type-checks in route options.

## Building a denial yourself

The formatter is exported, so a hook of your own can speak the same contract.

```ts
import { sendProblem } from 'fastify-agent-policy'

app.addHook('preHandler', async (request, reply) => {
  if (overBudget(request.agent)) {
    return sendProblem(reply, 'guard_failed', {
      retryable: false,
      detail: 'monthly call budget exhausted',
    })
  }
})
```

`sendProblem` returns the reply. Return it from the hook so Fastify stops the
lifecycle. It resolves `problemBaseUri` and the 401 challenge from the nearest
enclosing registration, installs the reply serializer, and sets
`WWW-Authenticate` on a 401 unless you already set one.

## License

MIT -- see [LICENSE](./LICENSE).

[rfc9457]: https://www.rfc-editor.org/rfc/rfc9457
