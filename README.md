[![pipeline status](https://gitlab.com/patatoid/boruta_auth/badges/master/pipeline.svg)](https://gitlab.com/patatoid/boruta_auth/-/commits/master)
[![coverage report](https://gitlab.com/patatoid/boruta_auth/badges/master/coverage.svg)](https://gitlab.com/patatoid/boruta_auth/-/commits/master)
[![downloads](https://img.shields.io/hexpm/dt/boruta)](https://hex.pm/packages/boruta)

# Boruta OAuth/OpenID Connect provider core
Boruta is the core of an OAuth 2.0 and OpenID Connect provider implementing according business rules. A generator is provided to create phoenix controllers, views and templates to have a basic provider up and running.

It is intended to follow RFCs:
- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
- [RFC 7009 - OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
- [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)

And specification from OpenID Connect:
- [OpenID Connect core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

This package is meant to help to provide authorization into Elixir applications. With it, you can perform part or all of authorization code, implicit, hybrid, client credentials, or resource owner password credentials grants flows. It also helps introspecting and revoking tokens.

## Documentation
Master branch documentation can be found [here](https://patatoid.gitlab.io/boruta_auth/readme.html)

Stable documentation is hosted on [hexdocs.pm](https://hexdocs.pm/boruta/api-reference.html)

## Integration example
An example of integration can be found [here](https://gitlab.com/patatoid/boruta_example)

## OpenID Certification

This package passed succesfully basic and implicit OpenID Profiles certification as of May 1st, 2022 for its version [2.1.0](https://hex.pm/packages/boruta/2.1.0). This certification was performed with the above example server which followed documented integration steps listed in the below guides section.

![OpenID Certification watermark](images/oid-certification-mark.png)

## Guides

Here are some guides helping the integration of OAuth/OpenID Connect in your systems:

- [Basic OAuth/OpenID Connect provider integration](guides/provider_integration.md)
- [How to create an OAuth client](guides/create_client.md)
- [Client request authorization](guides/authorize_requests.md)
- [Notes about pkce](guides/pkce.md)

## Feedback
It is a work in progress, all feedbacks / feature requests / improvements are welcome
