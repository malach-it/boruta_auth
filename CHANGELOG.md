# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) according to OAuth / OpenID connect specifications, changes may break in order to comply with those.

## [Unreleased]

### Added

- path wildcard (`**`) for redirect_uris

## [3.0.0-beta.4] - 2025-07-05

### Added

- support for oid4vci tx codes
- oauth token is returned in credential responses
- expose previous code in oauth tokens schema
- accept JWT typed oid4vci proofs
- signatures interface and adapters
- better errors on direct post requests
- verifiable credentials nested claims management
- better jwt_vc presentation support
- agent_credentials and agent_code flows
- check presentation against public client id
- better direct post success responses
- authorization code grant in credential issuance


### Fixed

- support for EdDSA signature algorithm
- sd jwt credentials claims
- clients did storage
- revoke public client cache on update
- presentations with public client
- empty code challenges

### Security

- revoke code on direct post success
- status tokens chains
- validate presentation resource owner if not public

## [3.0.0-beta.3] - 2024-11-21

### Changed

- `Boruta.Oauth.IdToken.generate/2` returns a tuple
- `Boruta.Oauth.ResourceOwners.get_by/1` is invoked with token scope as additional parameter
- resource owners extra_claims appear in id_token with a definition format

### Security

- oid4vp deeplinks (and QR codes) use codes time to live to avoid sharing to other holders

### Fixed

- adjustements to verifiable credential issuance and presentation

## [3.0.0-beta.2] - 2024-10-17

### Added

- OpenID for Verifiable Credentials Presentation implementation
- resolve EBSI dids

## [3.0.0-beta.1] - 2024-09-01

### Added

- OpenID for Verifiable Credentials Issuance implementation
- Self-Issued OpenID Provider v2 implementation
- Pushed Authorization Request implementation
- Demonstration Proof-of-Possesion implementation
- Direct post flow implementation
- Preauthorized code flow implementation
- support for vc+sd-jwt, jwt_vc_json credentials formats

## [2.3.4] - 2024-06-10

### Fixed

- revoke previous issued tokens in case of code replay (authorization code grant)

## [2.3.3] - 2024-03-20

### Removed

- removed analytics gathering repl on `boruta.gen.migration` task

### Security

- revoke previous issued tokens in case of code replay

## [2.3.2] - 2023-12-23

- Note that you must run the `boruta.gen.migration` task to keep your database schema up to date while upgrading to this version.

### Added

- clients have a `metadata` attribute where one can store json objects
- according to OpenID Connect core 1.0, clients have a `logo_uri` attribute
- `boruta.gen.migration` triggers a form to get statistics about boruta usage

## [2.3.1] - 2023-04-24

- Note that you must run the `boruta.gen.migration` task to keep your database schema up to date while upgrading to this version.

### Fixed
- public key is optional for oauth clients

## [2.3.0] - 2023-04-09

- Note that you must run the `boruta.gen.migration` task to keep your database schema up to date while upgrading to this version.

### Added

- configuration and support for client authentication methods (`client_secret_post`, `client_secret_basic`, `client_secret_jwt`, `private_key_jwt`) [RFC 7521](https://www.rfc-editor.org/rfc/rfc7521), [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)
- dynamic client registration support [OpenID Connect Dynamic Client Registration 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-registration-1_0.html)
- handle userinfo signed responses
- client key pair regeneration admin function `Admin.regenerate_client_key_pair/1,3`

## [2.2.2] - 2022-10-25

- Note that you must run the `boruta.gen.migration` task to keep your database schema up to date while upgrading to this version.

### Added

- allow lower case bearer authorization header
- prompt=none management for authorization code grant requests
- store the previous code associated with the delivered access token in authorization code grants
- prompt=none management for authorization code grant requests

## [2.2.1] - 2022-10-16

### Security

- remove symmetric keys from openid jwks

## [2.2.0] - 2022-09-13

- Note that you must run the `boruta.gen.migration` task to keep your database schema up to date while upgrading to this version.
- Upgrade to this version need you to invalidate the cache by running `Boruta.Config.cache_backend().delete_all()`

### Added

- confidential client management as stated in OAuth 2.0 RFC, documented [here](guides/confidential_clients.md). It defaults to false (already existing clients will not be confidential)
- token as the created `Boruta.Oauth.Token` attribute in `Boruta.Oauth.TokenResponse`

### Changed

- client credentials does not check client secret by default anymore, the client has to be set as confidential to do so

### Security

- enable refresh token rotation, revoke previous refresh token on successful refresh token requests
- fix redirect_uri injection in implicit, hybrid and code grants

## [2.1.5] - 2022-06-15

### Added

- id tokens include `kid` header with the corresponding client id
- `Boruta.Oauth.ResourceOwner` `extra_claims` attribute that defines claims to be included in id tokens

### Security

- do not not issue an access token in authorization code and hybrid grants if code was issued to an other client

### Fixed

- id token `at_hash` and `c_hash` binary sizes for SHA256 and SHA384 signature hash algorithms

## [2.1.4] - 2022-06-07

Note that you must run the `boruta.gen.migration` task to keep your database schema up to date while upgrading to this version.

### Added

- handle `response_mode` in hybrid requests
- client id_token validation for ecto adapter
- per client id token signature algorithm configuration (introduce a database schema change)

### Changed

- prefer `invalid_grant` to `invalid_code` and `invalid_refresh_token`
- error messages have been improved

## [2.1.3] - 2022-05-17

### Added

- handle `response_mode` in hybrid requests errors

### Fixed

- respond to authorize requests with `token_type` only when an access token is returned
- generated migrations can be rollbacked
- clients pkey constraint do not crash on admin create

## [2.1.2] - 2022-05-02

### Fixed

- hybrid requests shall return all errors as fragment

## [2.1.1] - 2022-04-30

### Fixed

- dialyzer warning on `Boruta.Oauth.Error` struct type

## [2.1.0] - 2022-04-29

### Added

- OpenID Connect jwks endpoint domain and application layer generation
- OpenID Connect userinfo endpoint domain and application layer generation

### Fixed

- OpenID Connect prompt=none login_required errors in domain

## [2.0.1] - 2022-04-12

### Added

- expose `Boruta.Oauth.Client.grant_types/0`
- expose `Boruta.Oauth.IdToken.signature_alg/0` and `Boruta.Oauth.IdToken.hash_alg/0`

### Changed

- `Admin.delete_inactive_tokens/0,1` does not return deleted tokens

### Fixed

- generated openid authorize controller prompt=none error params type

## [2.0.0] - 2022-01-26

### Added

- `Boruta.Ecto.Admin.get_scopes_by_names/1`
- `Boruta.Ecto.Admin.regenerate_client_secret/1,2`
- `Boruta.Ecto.Admin.delete_inactive_tokens/0,1`
- `Boruta.Ecto.Client.grant_types/0`
- ability to insert/update clients with given id/secret
- inserting/updating a client inserts non existing authorized_scopes
- `oauth_module` injection in `boruta.gen.controllers` generated controllers default to `Boruta.Oauth`

### Changed

- store previous token while refreshing access tokens (need to run `boruta.gen.migration` mix task to be up to date)
- `Boruta.Ecto.Admin.list_active_tokens/0,1` returns query result instead of an `Ecto.Query`
- `Boruta.Oauth.ResourceOwners.claims/2` callback takes a `Boruta.Oauth.ResourceOwner` struct instead of `sub` as parameter

## [2.0.0-rc.1] - 2021-11-17

### Fixed

- better Ecto errors management
- remove padding from pkce code challenge checks
- reduce resource_owners adapter calls

### Added

- domain wildcard for client redirect_uris

### Removed

- Ecto `ClientsAdapter.get_by(id: id, secret: secret)` is removed in preference of `ClientsAdapter.get_client(id)` and `Oauth.Client.check_secret(client, secret)`.
- Ecto `ClientsAdapter.get_by(id: id, redirect_uri: redirect_uri)` is removed in preference of `ClientsAdapter.get_client(id)` and `Oauth.Client.check_redirect_uri(client, redirect_uri)`.

## [2.0.0-rc.0] 2021-10-12

### Added

- [OpenID Connect core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) integration
  - hybrid flow
  - authorization code and implicit grants with OpenID Connect compatibility
- `public_revoke` per client configuration allowing to revoke tokens without providing client secret.
- `introspect` and `revoke` supported grant types per client configuration.

### Changed

- `Boruta.Oauth.AuthorizeResponse` and `Boruta.Oauth.TokenResponse` do not provide token value in `value` field but prefer giving value by token type `code`, `access_token` or `id_token`.
```
%AuthorizeResponse{
   type: "code",
   value: value,
   expires_in: 60
}
```
becomes
```
%AuthorizeResponse{
   type: :code,
   code: value,
   expires_in: 60
}
```
- add nonce column to tokens
- default column values migrations
- migration management `boruta.gen.migrations` does incremental changes

### Security

- codes are revoked after first usage

### Fixed

- `boruta.gen.controllers` generated paths in umbrella apps

## [1.2.1] - 2021-10-10

### Security

- remove redirect_uris regex pattern check

## [1.2.0] - 2021-09-15

### Added

- `public_refresh_token` per client configuration allowing to refresh tokens without providing client secret.
- `refresh_token_ttl` per client configuration setting refresh tokens duration (along with `refresh_tokne_max_ttl` :boruta mix configuration).
- `issuer` :boruta mix configuration.

### Fixed

- `boruta.gen.controllers` generated paths in umbrella apps.
- Refreshed tokens has associated access_token scope as default.
- Requests with no client secret won't raise an error.

### Changed

- `invalid_client` do not return neither format, nor redirect_uri in `Boruta.Oauth.Error`.

## [1.1.0] - 2021-08-16

### Added

- `AuthorizeApplication`, `IntrospectApplication`, `RevokeApplication`, and `TokenApplication` behaviours allowing to implement separately different OAuth use cases.
- `list_active_tokens` Ecto admin function
- `Boruta.AccessTokensAdapter`, `Boruta.CodesAdapter`, `Boruta.ClientsAdapter`, and `Boruta.ScopesAdapter` encapsulating adapters that are set in configuration.
- `Boruta.Oauth.AuthorizeResponse.redirect_to_url/1` function
- `Boruta.Oauth.Error.redirect_to_url/1` function
- `boruta.gen.controllers` mix task
- `Boruta.Ecto` schemas documentation

### Security

- do not issue access_tokens from other clients refresh tokens

### Fixed

- Internal server errors when no client_id provided to token and refresh_token grants

## [1.0.3] - 2021-07-29

### Security

- Refresh token revocation

## [1.0.2] - 2021-06-29

### Added

- Different OAuth flows integration guides

## [1.0.1] - 2021-03-10

### Fixed

- Migration fix generated by `mix boruta.gen.migration` task

### Added

- Documentation

## [1.0.0] - 2021-03-10
