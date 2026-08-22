import agentPolicy from './plugin.js'

export default agentPolicy
export { agentPolicy }

export {
  DuplicateRegistrationError,
  InvalidAgentIdentityError,
  InvalidAgentPolicyError,
  InvalidAgentPolicyOptionsError,
  MissingRiskTierError,
  RoutesBeforePluginError,
  validatePolicy,
} from './policy.js'

export {
  DEFAULT_PROBLEM_BASE_URI,
  DEFAULT_WWW_AUTHENTICATE,
  PROBLEM_CONTENT_TYPE,
  PROBLEM_TYPES,
  UnknownProblemKindError,
  buildProblem,
  isValidProblemBaseUri,
  sendProblem,
} from './problems.js'
export type {
  ProblemDefinition,
  ProblemDocument,
  ProblemExtensions,
  ProblemKind,
} from './problems.js'

export { bearerClaims } from './resolvers/bearer-claims.js'
export type {
  BearerClaimsMapper,
  BearerClaimsResolverOptions,
} from './resolvers/bearer-claims.js'

export { parseSignatureAgent, signatureAgent } from './resolvers/signature-agent.js'
export type { SignatureAgentResolverOptions } from './resolvers/signature-agent.js'

export { userAgentPattern } from './resolvers/user-agent-pattern.js'
export type { UserAgentPatternResolverOptions } from './resolvers/user-agent-pattern.js'

export { normalizeAgentOrigin, webBotAuth } from './resolvers/web-bot-auth.js'
export type {
  WebBotAuthResolverOptions,
  WebBotAuthResult,
} from './resolvers/web-bot-auth.js'

export type {
  AgentGuard,
  AgentIdentity,
  AgentIdentityResolver,
  AgentPolicy,
  AgentPolicyDefaults,
  AgentPolicyOptions,
  ApplyTo,
  ConfirmMode,
  DryRunMode,
  GuardResult,
  RegistrationOrder,
  ResolvedAgentPolicy,
  RiskTier,
  ScopeRequirement,
  SyncAgentIdentityResolver,
} from './types.js'
