# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) according to OAuth / OpenID connect specifications, changes may break in order to comply with those.

## [unreleased]

Note that you must run the `boruta.gen.migration` task to keep your database schema up to date while upgrading to this version.

### Added

- confidential client management as stated in OAuth 2.0 RFC, documented [here](guides/confidential_clients.md)
- token as the created `Boruta.Oauth.Token` attribute in `Boruta.Oauth.TokenResponse`

### Changed

- client credentials does not check client secret by default anymore, the client has to be set as confidential to do so

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
- `oauth_module` injection in `boruta.gen.controllers` generated controllers defalut to `Boruta.Oauth`

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

- `AuthorizeApplication`, `IntrospectApplication`, `RevokeApplication`, and `TokenApplication` behaviours allowing to implement separatly different OAuth use cases.
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

- Differents OAuth flows integration guides

## [1.0.1] - 2021-03-10

### Fixed

- Migration fix generated by `mix boruta.gen.migration` task

### Added

- Documentation

## [1.0.0] - 2021-03-10
