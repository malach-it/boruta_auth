# OAuth and OpenID business rules

This guide describes the OAuth, OpenID Connect, SIOPv2, OpenID4VP, and
OpenID4VCI behavior implemented by Boruta.

The rules below are derived from every active test under `test/boruta/oauth`
and `test/boruta/openid`, including integration flows and their supporting unit
modules. They describe observable behavior rather than every requirement in
the underlying specifications. Skipped tests are not treated as implemented
rules.

## Endpoint conventions

Boruta is a protocol and business-logic library, not an HTTP router. A host
application chooses its paths and calls the listed Boruta entry points from its
controllers or plugs. The paths in this guide are conventional suggestions.

Each entry point invokes callbacks from the corresponding application
behaviour. Those callbacks let the host application render redirects, JSON
responses, errors, or forms.

## Rules shared by OAuth flows

- Requests are validated before clients, grants, codes, or tokens are used.
- Unknown or malformed `grant_type` and `response_type` values are rejected.
- A request containing more than one DPoP header is rejected.
- The client must exist and have the requested grant type enabled.
- Confidential clients must authenticate with a valid secret.
- Redirect URIs must match a registered URI. Registered host wildcards and
  path wildcards are supported, but an unregistered or injected redirect URI
  is rejected.
- Public scopes are available without explicit client authorization.
- Private scopes require authorization.
- A scope explicitly authorized for the client or resource owner is accepted.
- Unknown or unauthorized scopes are rejected, except where a flow explicitly
  documents filtering.
- Cached clients, scopes, codes, and tokens must produce the same result as
  database-backed lookups.
- Expired and revoked authorization artifacts are rejected.
- DPoP-enforced clients require a valid proof. Boruta rejects malformed proofs,
  missing JWT headers, symmetric algorithms, malformed or invalid signatures,
  missing claims, an incorrect HTTP method, and an incorrect target URL.

## Client authentication rules

### Endpoints

| Authentication target | Method | Suggested endpoint | Boruta entry point |
|---|---|---|---|
| Token endpoint | `POST` | `/oauth/token` | `Boruta.Oauth.token/2` |
| Introspection endpoint | `POST` | `/oauth/introspect` | `Boruta.Oauth.introspect/2` |
| Revocation endpoint | `POST` | `/oauth/revoke` | `Boruta.Oauth.revoke/2` |

### Rules

- `client_secret_basic` reads the client credentials from HTTP Basic
  authentication.
- A malformed Basic header is rejected before the endpoint flow runs.
- `client_secret_post` reads the client ID and secret from the request body.
- POST authentication preserves a missing secret so public-client policy can
  decide whether it is allowed.
- A client can use only authentication methods configured in
  `token_endpoint_auth_methods`.
- A valid secret supplied through a disallowed authentication method is still
  rejected.
- `client_secret_jwt` is supported with the configured HMAC algorithm,
  including the tested HS256 and HS384 algorithms.
- `private_key_jwt` is supported with the configured RSA algorithm, including
  the tested RS256 and RS384 algorithms.
- Private-key JWT authentication can refresh a rotated verification key from
  the client's JWKS URI.
- Nil, malformed, incorrectly signed, or incorrectly keyed client assertions
  are rejected.
- A client assertion must contain `iss`, `aud`, and `exp`.
- The assertion expiration must be numeric and in the future.
- The assertion audience must equal the configured Boruta issuer.
- The assertion issuer supplies the client ID when the request does not carry a
  separate client ID.
- Client assertions are parsed consistently by token, introspection, and
  revocation requests.

## Scope rules

- A missing or empty scope is normalized to an empty scope string.
- Duplicate scopes contributed by the client and resource owner are removed.
- Public scopes are accepted for client and resource-owner authorization.
- Private scopes are accepted only when the relevant client or resource owner
  authorizes them.
- Nonexistent scopes and existing-but-unauthorized private scopes are rejected.
- A token can be narrowed only to scopes already carried by that token.
- A client authorization cannot expand the scope of an existing token.
- Even a public scope cannot be added during token narrowing if the original
  token did not authorize it.
- Supplying scope when the source token has no scope is rejected.

## Resource indicator rules

### Endpoints

| Flow | Method | Suggested endpoint |
|---|---|---|
| Authorization and pre-authorized offer | `GET` or `POST` | `/oauth/authorize` or `/openid/preauthorize` |
| Client credentials, code exchange, refresh, and pre-authorized token | `POST` | `/oauth/token` |

### Rules

- An omitted resource is valid when the client does not require one.
- Absolute URI and URN resource indicators are accepted.
- Relative, malformed, incorrectly percent-encoded, or URI-grammar-invalid
  resources are rejected.
- A resource containing a fragment is rejected.
- When a client has no resource allowlist, a syntactically valid resource is
  unrestricted.
- When a client has a resource allowlist, the resource is mandatory and must
  appear in that allowlist.
- Resource indicators are parsed for client credentials, authorization-code
  exchange, refresh-token, pre-authorized-code token, authorization, and
  pre-authorized-code authorization requests.
- A token request that omits resource inherits the resource authorized by the
  original grant.
- A token request cannot add a resource when the original grant had none.
- A token request cannot escalate from the originally authorized resource to a
  different resource.

## Request object rules

### Endpoints

| Request object use | Method | Suggested endpoint |
|---|---|---|
| Authorization request | `GET` or `POST` | `/oauth/authorize` or `/openid/authorize` |
| Token request | `POST` | `/oauth/token` |

### Rules

- An unsigned JWT request object is accepted for tested authorization and token
  requests.
- The JWT claims are merged into the corresponding Boruta request.
- A malformed inline request object is rejected.
- A request object can be fetched from `request_uri`.
- A malformed request URI, an HTTP fetch failure, or a fetched malformed JWT is
  rejected.
- A request URI is fetched using the requesting client's trusted authorities
  and trusted hosts.
- Successfully fetched request objects are parsed the same way as inline
  request objects.

## Outbound HTTP trust rules

These rules apply when Boruta retrieves request objects, client JWKS, and
credential status lists.

- Outbound retrieval requires HTTPS.
- Retrieval requires PEM-encoded trusted certificate authorities, an exact
  trusted host, or the configured Boruta issuer host.
- When trusted authorities are configured, the remote certificate must chain
  to one of those authorities.
- When only a trusted host is configured, the system certificate authorities
  are used.
- Trusted hosts are normalized by trimming whitespace, a trailing dot, and
  letter case before exact comparison. Host wildcards are not supported.
- The configured Boruta issuer host is implicitly trusted.
- When none of those trust sources accepts the destination, or when trust
  metadata is malformed or the certificate is untrusted, retrieval is
  rejected.

## Redirect URI matching rules

These rules apply to authorization endpoints that redirect to a client.

- A redirect URI without wildcards must match exactly, including query
  parameters.
- Regex-significant characters in a registered URI are treated literally.
- A single `*` wildcard matches one DNS-safe subdomain label.
- A wildcard subdomain label must be between 3 and 63 characters and may not
  contain characters outside the tested DNS-safe grammar.
- A single wildcard does not match a different base domain.
- A double `**` wildcard matches one nonempty path segment.
- Double-wildcard path segments can exceed the DNS label length limit.
- Path wildcards accept tested RFC 3986 unreserved characters,
  percent-encoded characters, sub-delimiters, colon, and `@`.
- A path wildcard can occur in the middle of a registered path while fixed
  prefixes and suffixes must still match.
- Mixed subdomain and path wildcards are supported.
- `**` is processed before `*`; the two wildcard forms remain semantically
  distinct.
- If a client registers several redirect patterns, matching any one is
  sufficient.
- An empty redirect list or a request matching none of the registered patterns
  is rejected.

## OAuth response and error encoding

- Authorization-code responses use query parameters by default.
- Access-token and default hybrid responses use URI fragments where required by
  the tested response type.
- Explicit `response_mode=query`, `response_mode=fragment`, and
  `response_mode=form_post` are honored for their supported response types.
- Code, access token, ID token, token type, expiry, and state are included only
  when applicable to the response.
- Existing query parameters in the redirect URI are preserved.
- `form_post` produces a parameter map for code, access-token, ID-token, and
  hybrid responses and removes nil values.
- An invalid client error has no redirect format, preventing redirection to an
  untrusted URI.
- Redirectable errors preserve state and use the flow's query, fragment, or
  form-post encoding.
- An error without a redirect URI produces no redirect URL.

## Authorization code grant

### Endpoints

| Stage | Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|---|
| Authorization | `GET` or `POST` | `/oauth/authorize` | `Boruta.Oauth.authorize/3` | `Boruta.Oauth.AuthorizeApplication` |
| Token exchange | `POST` | `/oauth/token` | `Boruta.Oauth.token/2` | `Boruta.Oauth.TokenApplication` |

### Authorization rules

- The request must contain a valid `code` response type, client ID, redirect
  URI, and authenticated resource owner.
- Anonymous wallet clients are not accepted by the regular authorization-code
  authorization flow.
- A successful request creates an authorization code bound to the client,
  resource owner, redirect URI, requested scope, and state.
- Confidential clients can request authorization codes.
- A supplied nonce is stored with the code.
- Authorization details are validated and stored with the code.
- The response returns state when state was supplied.
- Public, client-authorized, and resource-owner-authorized scopes are accepted.
- Private, unknown, and unauthorized scopes are rejected.
- A client without the authorization-code grant is rejected.
- Adapter persistence failures are returned as authorization errors.

### Token exchange rules

- The request must contain a valid client ID and authorization code.
- The redirect URI must match the URI bound to the code.
- The code must belong to the requesting client.
- Confidential clients must provide the correct secret.
- A code is single-use: a second exchange is rejected.
- Expired or revoked codes are rejected.
- A successful exchange creates an access token and refresh token and records
  the consumed code as the previous code.
- Scope and authorization details stored on the code are propagated to the
  token.
- An `openid` scope produces an ID token.
- A valid DPoP proof allows issuance of a DPoP-bound token.

### PKCE rules

- A client configured for PKCE must supply a code challenge during
  authorization.
- `plain` and `S256` challenges are supported.
- A missing challenge method defaults to `plain` for a plain challenge and to
  `S256` for a SHA-256 challenge in the tested authorization requests.
- Token exchange requires the matching verifier.
- A missing or incorrect verifier is rejected.
- Expired and revoked PKCE codes remain invalid.

## Pushed authorization requests

### Endpoints

| Stage | Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|---|
| Push request | `POST` | `/oauth/par` | <code>Boruta.Oauth.pushed_authorization_request/2</code> | `Boruta.Oauth.PushedAuthorizationRequestApplication` |
| Use request URI | `GET` or `POST` | `/oauth/authorize` | `Boruta.Oauth.authorize/3` | `Boruta.Oauth.AuthorizeApplication` |

### Rules

- The pushed request must contain a valid response type, client ID, redirect
  URI, scope, grant, and PKCE data when PKCE is required.
- Private, unknown, and unauthorized scopes are rejected.
- A client without the authorization-code grant is rejected.
- A valid request is persisted and returned through a request URI.
- The authorization endpoint accepts a valid stored request URI.
- An expired stored request is rejected.

## Implicit grant

### Endpoints

| Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|
| `GET` or `POST` | `/oauth/authorize` | `Boruta.Oauth.authorize/3` | `Boruta.Oauth.AuthorizeApplication` |

### Rules

- The request must have a valid token-bearing response type, client ID,
  redirect URI, resource owner, scope, and enabled implicit grant.
- Public and confidential clients are supported.
- Wildcard redirect URIs are supported; redirect injection is rejected.
- A valid request returns an access token.
- An ID token is returned only when the response requests one and the `openid`
  scope is present.
- An ID-token response requires a nonce.
- Missing `openid` scope suppresses the ID token without suppressing an
  otherwise valid access token.
- Public or authorized scopes are accepted; unknown or unauthorized scopes are
  rejected.
- Errors use the response mode appropriate to the request.

## Hybrid grant

### Endpoints

| Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|
| `GET` or `POST` | `/oauth/authorize` | `Boruta.Oauth.authorize/3` | `Boruta.Oauth.AuthorizeApplication` |

### Rules

- Supported combinations can return a code, access token, ID token, or all
  three.
- Invalid response modes are rejected.
- ID-token combinations require the `openid` scope and a nonce.
- A code-and-token response does not require a nonce when no ID token is
  returned.
- `query` response mode is supported for tested hybrid combinations; the
  default response encoding is used otherwise.
- Tokens can be bound to a requested resource.
- Client, redirect URI, resource owner, grant, scope, persistence, wildcard
  redirect, and PKCE rules are the same as the authorization-code flow.

## Client credentials grant

### Endpoints

| Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|
| `POST` | `/oauth/token` | `Boruta.Oauth.token/2` | `Boruta.Oauth.TokenApplication` |

### Rules

- Client authentication is mandatory.
- Invalid client IDs and secrets are rejected.
- The client must enable `client_credentials`.
- A successful request issues an access token.
- Public and authorized scopes are accepted.
- Private, unknown, and unauthorized scopes are rejected.
- DPoP-enforced clients receive a token only after all DPoP checks pass.

## Resource owner password credentials grant

### Endpoints

| Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|
| `POST` | `/oauth/token` | `Boruta.Oauth.token/2` | `Boruta.Oauth.TokenApplication` |

### Rules

- The request must contain valid client and resource-owner credentials.
- Invalid Basic authentication, client credentials, username, or password is
  rejected.
- Public clients and confidential clients authenticated with
  `client_secret_basic` or `client_secret_post` are supported.
- The client must enable the password grant.
- A successful request issues a token for the resource owner.
- Public or authorized scopes are accepted; unknown or unauthorized scopes are
  rejected.

## Refresh token grant

### Endpoints

| Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|
| `POST` | `/oauth/token` | `Boruta.Oauth.token/2` | `Boruta.Oauth.TokenApplication` |

### Rules

- The request must identify a valid client and refresh token.
- Confidential clients must provide their secret.
- The refresh token must belong to the requesting client.
- Invalid, expired, or revoked refresh tokens are rejected.
- A revoked associated access token prevents refresh.
- An expired associated access token can be refreshed while the refresh token
  remains valid.
- Public refresh is allowed only when `public_refresh_token` is enabled for the
  client.
- The client must enable the refresh-token grant.
- If scope is omitted, the new token inherits the associated access token's
  scope.
- Requested unknown or unauthorized scopes are rejected.
- A successful refresh rotates and revokes the previous refresh token and
  records the previous token relationship.

## Agent credentials grant

### Endpoints

| Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|
| `POST` | `/oauth/token` | `Boruta.Oauth.token/2` | `Boruta.Oauth.TokenApplication` |

### Rules

- The request and client credentials must be valid.
- The client must enable `agent_credentials`.
- Bind data and bind configuration must satisfy their schemas.
- A successful request issues an agent token and refresh token.
- Scope authorization follows the client-credentials rules.
- DPoP validation follows the shared DPoP rules.

## Agent code grant

### Endpoints

| Stage | Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|---|
| Authorization | `GET` or `POST` | `/oauth/authorize` | `Boruta.Oauth.authorize/3` | `Boruta.Oauth.AuthorizeApplication` |
| Token exchange | `POST` | `/oauth/token` | `Boruta.Oauth.token/2` | `Boruta.Oauth.TokenApplication` |

### Rules

- Token exchange validates the request, client, code, redirect URI, grant,
  expiry, revocation, client ownership, and confidential-client secret.
- Codes are single-use.
- PKCE `plain` and `S256` are supported.
- A successful request issues an agent token and refresh token.
- Bind data, scope, authorization details, and previous-code relationships are
  propagated.
- An `openid` scope can produce an ID token.
- A valid DPoP proof is accepted.
- DID wallet clients can use `agent_code`; the public client must advertise the
  grant.

## Token introspection

### Endpoints

| Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|
| `POST` | `/oauth/introspect` | `Boruta.Oauth.introspect/2` | `Boruta.Oauth.IntrospectApplication` |

### Rules

- The request and introspecting client credentials must be valid.
- The client must enable `introspect`.
- An inactive token produces a successful response with `active: false`.
- An active token returns its authorization data, including its resource when
  present.
- Client authentication is accepted from the tested authorization header and
  body forms.
- The response issuer comes from Boruta configuration and supports a custom
  issuer.

## Token revocation

### Endpoints

| Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|
| `POST` | `/oauth/revoke` | `Boruta.Oauth.revoke/2` | `Boruta.Oauth.RevokeApplication` |

### Rules

- The request and client authentication must be valid.
- Client credentials are accepted through the tested Basic header and body
  forms.
- Access tokens, refresh tokens, agent tokens, and agent refresh tokens can be
  revoked.
- Token type hints are supported.
- Revoking an unknown token is idempotent and returns success.
- A client with `public_revoke` enabled can revoke without a client secret.

## OpenID Connect authorization

### Endpoints

| Stage | Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|---|
| Authorization | `GET` or `POST` | `/openid/authorize` | `Boruta.Oauth.authorize/3` | `Boruta.Oauth.AuthorizeApplication` |
| Token exchange | `POST` | `/oauth/token` | `Boruta.Oauth.token/2` | `Boruta.Oauth.TokenApplication` |

### Rules

- OpenID authorization reuses the authorization-code, implicit, and hybrid
  validation rules.
- An ID token is issued only for an OpenID request with `openid` scope.
- Nonce requirements are enforced for the tested implicit and hybrid ID-token
  responses.
- The authorization code stores the nonce for later ID-token issuance.
- Successful authorization-code and agent-code exchanges can issue an ID token.
- `post`, `direct_post`, JWT-secured direct-post, and JWE-secured direct-post
  response handling are supported by the tested SIOPv2 and presentation flows.

### ID-token construction rules

- ID tokens can be generated from an authorization code, an access token, both
  artifacts, or the common base token data.
- The applicable code and access-token hashes are included for the tested
  response shape.
- Resource-owner extra claims are added to the ID token.
- RS256, RS384, HS256, HS384, and HS512 signing configurations are supported.
- A nil or empty nonce is omitted from the claims.
- A nonempty nonce is included unchanged.
- Claim values that are already valid JSON values are preserved.
- Claim definitions with display metadata are normalized without leaking
  display-only metadata into the token payload.
- Claims configured as hidden are omitted.

## UserInfo

### Endpoints

| Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|
| `GET` or `POST` | `/openid/userinfo` | `Boruta.Openid.userinfo/2` | `Boruta.Openid.UserinfoApplication` |

### Rules

- A valid access token is required.
- Bearer tokens are accepted through the Authorization header and the tested
  POST body form.
- Missing, malformed, and invalid tokens are rejected.
- The token must belong to a resource owner.
- A valid request returns the resource owner's claims.
- When `userinfo_signed_response_alg` is configured, UserInfo is returned as a
  signed JWT.
- Unsigned UserInfo responses use `application/json`; signed responses use the
  JWT content type.
- The response payload is a JSON object for unsigned responses and the compact
  JWT for signed responses.

## JSON Web Key Set

### Endpoints

| Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|
| `GET` | `/.well-known/jwks.json` | `Boruta.Openid.jwks/2` | `Boruta.Openid.JwksApplication` |

### Rules

- The JWKS contains the public client's signing key.
- Public keys for configured clients are listed without private key material.

## Dynamic client registration

### Endpoints

| Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|
| `POST` | `/openid/register` | `Boruta.Openid.register_client/3` | `Boruta.Openid.DynamicRegistrationApplication` |

### Rules

- Invalid registration data is rejected.
- Registration uses a dedicated changeset that only accepts client name,
  redirect URIs, token endpoint authentication metadata, JWKS metadata, and
  logo URI, plus the trusted authorities and trusted hosts required for JWKS
  retrieval. Other administrative client attributes are ignored.
- Dynamically registered clients default to the `client_credentials` and
  `authorization_code` grants.
- Redirect URIs containing fragments are rejected.
- Client name and token endpoint authentication method are persisted.
- Inline JWKS input selects the advertised public key and signing algorithm.
- A reachable and trusted `jwks_uri` is fetched and its key is stored.
- An untrusted host or certificate, insufficient trust configuration, or
  another `jwks_uri` fetch failure rejects registration with a changeset
  error.

## SIOPv2 direct post

### Endpoints

| Stage | Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|---|
| Authorization | `GET` or `POST` | `/openid/authorize` | `Boruta.Oauth.authorize/3` | `Boruta.Oauth.AuthorizeApplication` |
| Wallet response | `POST` | `/openid/direct_post` | `Boruta.Openid.direct_post/3` | `Boruta.Openid.DirectPostApplication` |

### Rules

- A valid signed ID token and an existing, active authorization code are
  required.
- A malformed ID token or unknown, expired, or revoked code is rejected.
- PKCE-enabled clients must provide the matching verifier.
- Plain and encrypted direct-post payloads are supported.
- Successful processing records the wallet subject and returns the redirect
  URI and state bound to the code.
- DID and non-DID public-client identifiers are supported by the tested
  public-client checks.
- Metadata policies support:
  - `one_of`: at least one client ID from the proof/code chain must match.
  - `superset_of`: every configured client ID must occur in the proof/code
    chain.
- Adapter string errors are returned with code context; other adapter errors
  are safely inspected.

## OpenID4VP direct post

### Endpoints

| Stage | Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|---|
| Presentation request | `GET` or `POST` | `/openid/authorize` | `Boruta.Oauth.authorize/3` | `Boruta.Oauth.AuthorizeApplication` |
| Presentation response | `POST` | `/openid/direct_post` | `Boruta.Openid.direct_post/3` | `Boruta.Openid.DirectPostApplication` |

### Presentation authorization rules

- Presentation authorization supports response types beginning with `code`,
  `id_token`, or `vp_token`; unsupported response types are rejected.
- A `vp_token` response is authorized only when the requested scope selects an
  entry in the resource owner's presentation configuration. Without such an
  entry, the response falls back to `id_token`.
- A DID client ID uses Boruta's configured public client. Other client IDs must
  identify a registered client whose redirect URI and grant type are valid.
- The resource owner must be authorized. An agent token can authorize the
  resource owner and contributes its claims to scope authorization.
- Public, client-authorized, resource-owner-authorized, and selected
  presentation scopes are retained. Unknown and unauthorized scopes are
  filtered from the authorized scope and recorded as requested scopes.
- Authorization details are validated before a presentation code is created.
- An optional existing code must be active and valid. It is linked as the
  previous code, forming the code chain used by later presentation checks.
- The selected presentation definition, nonce, state, scopes, redirect URI,
  public client ID, agent token, PKCE data, and client-encryption parameters are
  bound to the created code.
- A resource-owner code verifier overrides request PKCE parameters and is
  stored as a plain code challenge.
- Agent-token and client-encryption data from a previous code take precedence
  when the new code is created.
- Requests beginning with `vp_token` produce a verifiable-presentation
  response. Requests beginning with `code` or `id_token` produce a SIOPv2
  response.
- The response uses the client's configured response mode. The tested
  `direct_post` and `post` modes return the stored code and presentation
  request data to the wallet.

### Direct-post rules

- A valid signed VP token and an existing, active code are required.
- PKCE-enabled clients must provide the matching verifier.
- Plain and encrypted direct-post payloads are supported.
- A presentation submission is required when the code contains a presentation
  definition.
- Malformed presentation-submission JSON is rejected.
- The descriptor map and submitted presentation must satisfy the stored
  presentation definition.
- A code-chain metadata policy can accept or reject the presentation.
- Public-client verification checks the current active DID and can fall back to
  an earlier active DID in the code chain.
- Revoked codes are ignored when searching the chain.
- Verification fails when no active DID in the chain validates the token.
- A code chain whose last code contains the valid client is accepted.

Skipped replay and subject-mismatch cases are intentionally not documented as
enforced rules.

### VP-token validation rules

- The VP token must be a string containing a valid, unexpired signed JWT;
  malformed values and signature failures are rejected.
- A JWT carrying an embedded key is rejected when that key does not verify its
  signature.
- A `did:key` key identifier can be resolved to verify a VP token.
- When both `jwk` and `kid` are present, the embedded `jwk` takes precedence.
- A presentation must contain at least one verifiable credential.
- The number of input descriptors must match the number of descriptor-map
  entries.
- Every descriptor-map entry must resolve to a valid credential and satisfy
  its input descriptor.
- Unknown credential formats and malformed descriptors are rejected.
- A credential must contain an expiration date and must not be expired.
- A credential must contain `validFrom`, either at the root or in its supported
  nested representation, and that date must not be in the future.
- Status-list credentials are fetched using the client's outbound trust
  configuration and verified. Revoked entries, invalid status-list
  credentials, and fetch or trust failures reject the presentation.
- Presentation-exchange constraints support `contains` and regular-expression
  `pattern` filters.
- A constraint without a filter is accepted; an unknown filter type is
  rejected.

## Preauthorization

This is Boruta's OAuth preauthorization response flow, distinct from the
OpenID4VCI pre-authorized code flow described below.

### Endpoints

| Stage | Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|---|
| Preauthorize | `GET` or `POST` | `/oauth/preauthorize` | `Boruta.Oauth.preauthorize/3` | `Boruta.Oauth.AuthorizeApplication` |

### Rules

- Client, redirect URI, resource owner, scope, and grant are validated.
- Wildcard redirect URIs are supported.
- Public or authorized scopes are accepted.
- Unknown or unauthorized scopes are rejected.
- A successful request can produce the tested preauthorization response and
  token.

## OpenID4VCI pre-authorized code flow

### Endpoints

| Stage | Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|---|
| Credential offer | `GET` or `POST` | `/openid/preauthorize` | `Boruta.Oauth.authorize/3` | `Boruta.Oauth.AuthorizeApplication` |
| Token exchange | `POST` | `/oauth/token` | `Boruta.Oauth.token/2` | `Boruta.Oauth.TokenApplication` |

### Offer rules

- Request schema, client, resource owner, grant, and supplied code are
  validated.
- Invalid, expired, and revoked codes are rejected.
- Unknown or unauthorized scopes are filtered from the offer.
- Draft 11 and draft 13 credential offers are supported.
- Offers can be bound to a resource.
- An agent token can authorize an offer.
- Transaction-code configuration is included when required.

### Token rules

- The request and pre-authorized code must be valid.
- Expired and revoked codes are rejected.
- A required transaction code must match.
- A successful exchange issues an access token carrying the credential
  authorization.
- Resource binding is propagated from the pre-authorized code.
- Agent-token and transaction-code variants are supported.

## OpenID4VCI credential issuance

### Endpoints

| Stage | Method | Suggested endpoint | Boruta entry point | Application behaviour |
|---|---|---|---|---|
| Credential | `POST` | `/openid/credential` | `Boruta.Openid.credential/4` | `Boruta.Openid.CredentialApplication` |
| Deferred credential | `POST` | `/openid/credential/deferred` | `Boruta.Openid.defered_credential/2` | `Boruta.Openid.CredentialApplication` |

### Credential rules

- A valid bearer access token is required.
- Missing, malformed, invalid, expired, or revoked bearer tokens are rejected.
- Encrypted credential requests are decrypted with the token's client; a
  malformed encrypted request is rejected.
- Credential request schema and requested credential identifiers are
  validated.
- The access token must reference an existing previous code and a valid code
  chain.
- The requested credential must be allowed by the token's authorization
  details and the resource owner's credential configuration.
- JWT proofs are validated.
- When public-client checking is enabled, the proof key must verify against an
  active DID in the code chain.
- Metadata `one_of` and `superset_of` client-ID policies are enforced.
- A successful immediate request returns the credential and revokes the
  applicable code chain.
- Invalid code chains and metadata policies are rejected.

### Credential proof rules

- The proof object must satisfy the supported proof schema, including
  `proof_type` and a JWT value.
- Malformed and non-string proof values are rejected.
- Proof JWTs must use an asymmetric signing algorithm.
- The proof type header must be `openid4vci-proof+jwt` or `JWT`.
- The protected header must contain proof material through `jwk` or `kid`.
- When both `jwk` and `kid` are present, the embedded `jwk` takes precedence.
- A `did:key` key identifier can be resolved to verify the proof.
- The proof must contain the required `aud` and `iat` claims.
- A proof whose embedded key does not match its signature is rejected.

### Credential selection and format rules

- Credential configurations can be selected through an authorized
  configuration scope on the access token.
- The implementation can derive configuration scopes from the preceding
  authorization-code chain.
- A configuration scope that was not authorized is rejected.
- For DID resource owners, the configured default credential configuration is
  used when applicable.
- Draft 11 requests select a credential configuration by credential types.
- Draft 13 requests select a credential configuration from the token scope and
  credential identifier.
- Credential configurations with an unknown protocol version are ignored.
- The supported output formats are `jwt_vc`, `jwt_vc_json`, and `vc+sd-jwt`.
- Nested claim selection is supported for each output format.
- Unsupported formats are rejected.
- A signing failure is propagated for each supported format.
- Credential authorization details must be valid JSON and match their schema;
  malformed JSON and schema violations are rejected.

### Credential status rules

- `vc+sd-jwt` credentials can be issued with valid, suspended, revoked, and
  expired status information.
- Status-list salts can be generated for valid, suspended, and revoked
  credentials.
- Status-list generation remains valid across at least one thousand generated
  salts.
- Invalid status-list input is rejected.

### Deferred credential rules

- A credential configuration marked deferred returns an acceptance token
  instead of the final credential.
- Failure to persist a deferred credential is returned as an internal error.
- The deferred endpoint requires a valid bearer acceptance token.
- An unknown acceptance token returns credential-not-found.
- A valid acceptance token returns the stored credential.

## Test traceability

This inventory covers every active test under `test/boruta/oauth` and
`test/boruta/openid`, plus the shared outbound-trust tests in
`test/boruta/http_client_test.exs`, at the time it was generated. Several tests
exercise the same rule with different inputs, so the number of rule bullets is
deliberately smaller than the number of test cases.

| Test layer | OAuth | OpenID | Shared trust | Total |
|---|---:|---:|---:|---:|
| Active integration and flow cases | 260 | 107 | 0 | 367 |
| Active supporting unit cases | 193 | 73 | 10 | 276 |
| **All active cases represented by this guide** | **453** | **180** | **10** | **643** |
| Skipped cases, not asserted as implemented rules | 1 | 6 | 0 | 7 |
| **All discovered cases** | **454** | **186** | **10** | **650** |

Outbound request trust is exercised by 28 active cases across the shared HTTP
client, OAuth request-object and client-authentication tests, dynamic
registration, and credential status-list validation. Fourteen additional
administration tests cover persistence and validation of client trust
configuration outside this guide's protocol-rule inventory.

The integration and flow rules are exercised by:

- `test/boruta/oauth/integration/agent_credentials_grant_test.exs`
- `test/boruta/oauth/integration/authorization_code_grant_test.exs`
- `test/boruta/oauth/integration/client_credentials_grant_test.exs`
- `test/boruta/oauth/integration/common_grant_test.exs`
- `test/boruta/oauth/integration/hybrid_test.exs`
- `test/boruta/oauth/integration/implicit_grant_test.exs`
- `test/boruta/oauth/integration/introspect_test.exs`
- `test/boruta/oauth/integration/preauthorize_test.exs`
- `test/boruta/oauth/integration/pushed_authorization_request_test.exs`
- `test/boruta/oauth/integration/refresh_token_test.exs`
- `test/boruta/oauth/integration/resource_owner_password_credentials_grant_test.exs`
- `test/boruta/oauth/integration/revoke_test.exs`
- `test/boruta/openid/integration/credential_test.exs`
- `test/boruta/openid/integration/direct_post_test.exs`
- `test/boruta/openid/integration/dynamic_registration_test.exs`
- `test/boruta/openid/integration/jwks_test.exs`
- `test/boruta/openid/integration/preauthorized_code_grant_test.exs`
- `test/boruta/openid/integration/userinfo_test.exs`

Supporting validation, schema, matching, encoding, token-construction,
credential, and presentation rules are exercised by the remaining test modules
directly under `test/boruta/oauth` and `test/boruta/openid`, including:

- OAuth authorization, client authentication, client schema, error, request,
  response, resource-indicator, scope, and token modules.
- OpenID ID-token, UserInfo-response, verifiable-credential, and
  verifiable-presentation modules.

### Skipped expectations

The following seven skipped cases are excluded from the business-rule inventory
because the test suite does not currently assert that they work:

- Authorization code: reject a SIOPv2 request without a nonce.
- SIOPv2 direct post: reject a code subject mismatch.
- SIOPv2 direct post: reject authentication with the tested bad public client.
- OpenID4VP direct post: reject a code subject mismatch.
- OpenID4VP direct post: reject replay of a previously processed response.
- OpenID4VP direct post: reject replay when the valid DID is in the middle of a
  code chain.
- VP-token validation: validate revocation against the external EBSI
  status-list example.

The full test suite has one additional skipped administration case for creating
a client with a universal key; it is outside this protocol-rule inventory.

When tests and this guide disagree, update the guide together with the behavior
and its tests.
