# fastify-agent-policy

Declare what an AI agent caller is allowed to do on a Fastify route, and deny
it with an answer the agent can act on.

`fastify-web-bot-auth` answers *who is this*. This plugin answers *what is it
allowed to do*.

> **Status.** This release enforces identity, risk tiers, scopes and guards,
> and ships the full RFC 9457 error contract. Dry-run and two-phase
> confirmation are declared and validated now, and enforced in a follow-up
> release. See [What is enforced today](#what-is-enforced-today).

> **Upgrading from the previous release.** `scopes` and `guard` were declared
> and validated but **inert** -- a route could require `orders:refund` and be
> called by an agent holding nothing. They now deny live traffic. Before you
> deploy, check that the scopes your resolver emits actually match the ones
> your routes declare (they are compared by exact string equality), and that
> every `guard` you have written returns `true` rather than a truthy value.
> Two registration shapes that used to boot now fail fast: `maxRisk: {}` and a
> nested registration. See [Migrating to enforcement](#migrating-to-enforcement).

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

The logged `reason` is more specific than the `detail` the caller reads. A
`risk_tier_blocked` reason names the tier and the allowance it failed; a
`guard_failed` reason from a throwing guard carries the error. Neither reaches
the response body -- a caller must not be able to enumerate your `maxRisk`
table, and a guard message can name an internal host.

## Usage

```ts
import Fastify from 'fastify'
import agentPolicy, { webBotAuth } from 'fastify-agent-policy'

const app = Fastify()

await app.register(agentPolicy, {
  identify: webBotAuth(),      // pluggable; see Resolvers
  applyTo: 'agents',           // 'agents' (default) | 'all'
  defaults: { risk: 'write' }, // inherited by every route policy
  maxRisk: {                   // highest tier each agent class may call
    trusted: 'destructive',
    verified: 'write',
    default: 'read',
  },
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

Register the plugin **once per application**, at the level that owns the
routes. Two shapes are rejected at boot:

| Shape | Code |
|---|---|
| A second registration on the same instance | `FST_AGENT_POLICY_DUPLICATE_REGISTRATION` |
| A registration inside a scope that already has one from an ancestor | `FST_AGENT_POLICY_NESTED_REGISTRATION` |

Both would run `identify()` and every policy check **twice per request**. That
is not merely wasteful: a guard is userland code that may have a side effect,
and the spend-counter guard in [Guards](#guards) would charge every caller
twice. A nested registration is worse still, because `fastify-plugin` skips
encapsulation -- its hooks join the ancestor's rather than replacing them, and
the ancestor's `onRoute` reaches each route first, so the nested
registration's own `defaults` are silently ignored.

**Sibling encapsulated scopes are fine**, and each keeps its own resolver, base
URI and challenge -- neither is inside the other:

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

If you need different policy for different route groups, reach for `defaults`
and per-route `config.agent` first. Sibling scopes are for a genuinely
different *identity* scheme, not a different allowance.

## Plugin options

| Option | Type | Default | Notes |
|---|---|---|---|
| `identify` | `(request) => AgentIdentity \| null \| Promise<...>` | *required* | There is no default identity scheme. Guessing one is how policy ends up attached to a spoofable header. |
| `applyTo` | `'agents' \| 'all'` | `'agents'` | `'all'` denies unidentified callers on policed routes with `agent_identity_required`. |
| `defaults` | `AgentPolicy` | `{}` | Merged underneath every route policy. |
| `maxRisk` | `Record<string, RiskTier>` | *unset* | The highest risk tier each agent `class` may call, with a `default` fallback. Unset disables the tier check. See [Risk tiers](#risk-tiers). |
| `problemBaseUri` | `string` | `https://github.com/umxr/fastify-agent-policy/problems` | Base for the `type` URIs. Must parse as a URI. |
| `wwwAuthenticate` | `string` | `Bearer realm="agent-policy"` | The challenge sent with a 401, which RFC 9110 makes mandatory. Set it to match what your resolver reads. |
| `registrationOrder` | `'strict' \| 'warn' \| 'off'` | `'strict'` | What to do about routes registered before the plugin. See [Registration order](#registration-order). |

## Route policy

Declared under `config.agent`, and validated when the route registers.

| Property | Type | Notes |
|---|---|---|
| `risk` | `'read' \| 'write' \| 'destructive'` | Required, here or in `defaults.risk`. Checked against the plugin's `maxRisk`. |
| `scopes` | `string[] \| { any: string[] } \| { all: string[] }` | A bare array means all of them. Matched by exact string equality. |
| `dryRun` | `false \| 'preview' \| 'handler'` | Declared and validated; enforced by a later release. |
| `confirm` | `false \| 'two-phase'` | Declared and validated; enforced by a later release. |
| `guard` | `(request, agent) => boolean \| { allow, reason }` | May be async. Runs last. |

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
| `FST_AGENT_POLICY_NESTED_REGISTRATION` | The plugin was registered inside a scope that already has it from an ancestor. See [Registering more than once](#registering-more-than-once). |
| `FST_AGENT_POLICY_UNKNOWN_PROBLEM` | `sendProblem`/`buildProblem` was asked for a type that does not exist. |
| `FST_AGENT_POLICY_INVALID_IDENTITY` | An `identify()` resolver returned something that is not an identity. Request time, not boot. |

## Enforcement

Checks run in one fixed order and stop at the first refusal:

| # | Check | Hook | Denial |
|---|---|---|---|
| 1 | **Risk tier** -- is this route's `risk` within the caller's `maxRisk` allowance? | `onRequest` | `403 risk_tier_blocked` |
| 2 | **Scopes** -- does the caller hold what `scopes` requires? | `onRequest` | `403 scope_denied` |
| 3 | **Guard** -- does the route's own predicate allow it? | `preHandler` | `403 guard_failed` |

The order is part of the contract, not an accident. A request that fails
several checks always yields the same problem type, so an agent that fixes its
scopes and retries does not then discover a tier ceiling it could have been
told about first. The order is also cheapest-first: the guard is userland code
that may be async and may call out to something, so it runs only once the rest
have passed.

### Why the guard runs later

The first two checks answer from data already in hand, so they run in
`onRequest` -- the earliest hook there is -- and turn a caller away before the
body is even read.

**A guard runs in `preHandler` instead, where `request.body` is parsed and
schema-validated.** A guard exists to inspect the request; the canonical
example is `request.body.amount <= 500`. In `onRequest` the body is not parsed
yet, so a guard like that reads `undefined` and refuses every valid call.

The order survives the split, because a denial in `onRequest` ends the
lifecycle before `preHandler` runs. One consequence is worth knowing:

> A request whose body fails the route's own JSON schema gets Fastify's
> `400 FST_ERR_VALIDATION` **before the guard is consulted at all**. Risk and
> scope denials still precede validation; only the guard sits behind it.

**Only identified callers are checked.** Under the default
`applyTo: 'agents'`, a request with no agent identity is human traffic: it
passes through a policed route untouched, and no tier, scope or guard check
runs against it. Use `applyTo: 'all'` to deny unidentified callers on policed
routes with `agent_identity_required` instead.

Denials are sent, never thrown, so a host application's root `setErrorHandler`
cannot rewrite the body an agent reads. The handler never runs.

### Risk tiers

`maxRisk` maps an agent `class` to the highest tier that class may call.
Tiers are ordered `read` < `write` < `destructive`, and the allowance is
inclusive.

```ts
await app.register(agentPolicy, {
  identify: webBotAuth(),
  maxRisk: {
    trusted: 'destructive',  // may call anything
    verified: 'write',       // may not call a destructive route
    default: 'read',         // every other class, including unknown ones
  },
})
```

- **Leave `maxRisk` unset** and the tier check is skipped entirely. Scopes and
  guards still run.
- **A class the map does not list** falls back to `default`.
- **A class the map does not list, with no `default`** is denied. So is an
  identity carrying no `class` at all. An unrecognized class is exactly when
  guessing costs the most, so it fails closed.
- **An empty map is rejected at boot.** `maxRisk: {}` matches no class and has
  no `default`, so it denies every agent on every policed route while reading
  as "nothing configured". Omit the option to disable the check.

> **`default` is a reserved key.** An agent class literally named `default`
> cannot have its own entry -- it takes the fallback allowance, and any entry
> you write for it becomes the fallback for every other unlisted class too. If
> your resolver can emit that class name, rename it.

A blocked call gets `403 risk_tier_blocked` with `retryable: false`. The
response never names the configured allowance or the route's tier -- that
would let an agent enumerate your policy table. The reason is in the log.

### Scopes

Scopes match by **exact string equality**. There is no wildcard, no hierarchy
and no prefix rule: an agent holding `orders` or `orders:*` does not satisfy a
route requiring `orders:refund`, and `orders:*` is a scope literally named
`orders:*`.

| Declaration | Satisfied when |
|---|---|
| `['a', 'b']` | The agent holds **both**. A bare array is all-of. |
| `{ all: ['a', 'b'] }` | The same thing, said out loud. |
| `{ any: ['a', 'b'] }` | The agent holds **at least one**. |

A denial is `403 scope_denied` carrying `requiredScopes` -- the list the route
declared, so the agent can ask for the right thing rather than guess.

`defaults.scopes` are **replaced** by a route's own `scopes`, never unioned
with them. The merge is a shallow `{ ...defaults, ...declared }`: a route that
declares `scopes` states its complete requirement.

### Guards

A guard is the escape hatch for anything the declarative members cannot say --
a spend limit, a tenant match, a time window.

```ts
app.post('/orders/:id/refund', {
  config: {
    agent: {
      risk: 'destructive',
      guard: async (request, agent) => {
        // `request.body` is parsed by the time a guard runs.
        const { amount } = request.body as { amount: number }
        if (amount > 500) return { allow: false, reason: 'refunds over $500 need a human' }

        const spent = await refundsToday(agent.id)
        if (spent > 10_000) return { allow: false, reason: 'daily refund cap reached' }
        return true
      },
    },
  },
}, handler)
```

- `true` and `{ allow: true }` allow. Anything else denies, including a
  malformed return value -- a guard that cannot say yes does not mean yes.
- `{ allow: false, reason }` denies with `403 guard_failed`, and `reason`
  becomes the problem's `detail`. It is the one message the caller sees, so
  write it for the agent.
- **A guard that throws** is a failure to decide, not a decision. The error
  goes to `request.log.error` and never to the caller, and the denial is
  `guard_failed` with `retryable: true`. This mirrors how a throwing
  `identify()` is handled.

`retryable` is how an agent tells those two apart, and it is the only signal
that does: **the status is `403` either way**, because `guard_failed`'s status
is fixed in the frozen type table and an undecidable guard does not get to
become a `5xx`.

| Outcome | `retryable` | What the agent should do |
|---|---|---|
| The guard refused | `false` | Do not repeat this request unchanged. |
| The guard could not decide | `true` | Retry; the refusal was not about you. |

**A guard's `reason` is public.** It becomes the problem's `detail` and is sent
to the caller, so write it for the agent and keep secrets out of it. Control
characters are stripped and the string is capped at 200 characters; a reason
left empty by that falls back to generic wording.

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

## Migrating to enforcement

Everything below was declared and validated in the previous release and inert
at request time. Nothing changes shape; things start denying.

| What changed | What to check before deploying |
|---|---|
| `scopes` now denies | The scopes your resolver emits match the ones your routes declare, **by exact string equality**. An identity with no `scopes` member satisfies no requirement at all -- and that is what every built-in resolver emits unless you configure one. |
| `guard` now denies | Every guard returns `true` or `{ allow: true }`. A truthy-but-not-`true` return (`1`, `'yes'`) denies. Guards run in `preHandler`, so `request.body` is available. |
| `risk` now denies | Only if you set `maxRisk`. Leave it unset and nothing changes. |
| `maxRisk: {}` now throws | It denied everything while reading as "unconfigured". Omit the option instead. |
| Nested registration now throws | It ran every check twice per request. Move the registration up, or use sibling scopes. |

The quickest way to find the gap before your agents do: turn on `maxRisk`
last. Deploy with scopes and guards enforcing, watch the `agentPolicy` denial
records in your logs, and add the tier ceiling once they are quiet.

## What is enforced today

| Requirement | Declared | Validated at boot | Enforced at request time |
|---|---|---|---|
| FR1 identity, `request.agent` | yes | n/a | yes |
| FR2 route policy | yes | yes -- shape, and `risk` resolution | yes |
| FR8 error contract | yes | yes | yes |
| FR3 scopes | yes | yes | yes -- exact match, `403 scope_denied` |
| FR4 risk tiers | yes | yes | yes -- when `maxRisk` is set, `403 risk_tier_blocked` |
| FR5 dry-run | yes | yes | not yet |
| FR6 confirmation | yes | yes | not yet |
| FR7 guards | yes | yes | yes -- `403 guard_failed` |

Enforcement only ever applies to an identified caller. Under the default
`applyTo: 'agents'`, anonymous traffic passes a policed route unchecked.

`dryRun` and `confirm` are checked for shape today and start being enforced
when you upgrade. Nothing in the config block changes shape.

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
| `InvalidAgentPolicyError`, `MissingRiskTierError`, `InvalidAgentPolicyOptionsError`, `RoutesBeforePluginError`, `DuplicateRegistrationError`, `NestedRegistrationError`, `UnknownProblemKindError`, `InvalidAgentIdentityError` | The coded error classes, for `instanceof` checks in your own boot tests. |
| `validatePolicy(routeName, policy, defaults?)` | The registration-time validator, returning the merged policy with `risk` resolved. Useful if you build route options programmatically and want to fail before Fastify sees them. |

### Types

`AgentIdentity`, `AgentIdentityResolver`, `SyncAgentIdentityResolver`,
`AgentPolicy`, `AgentPolicyDefaults`, `ResolvedAgentPolicy`,
`AgentPolicyOptions`, `ApplyTo`, `RegistrationOrder`, `RiskTier`,
`MaxRiskAllowance`, `ScopeRequirement`, `DryRunMode`,
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
