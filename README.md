[![pipeline status](https://gitlab.com/patatoid/boruta_auth/badges/master/pipeline.svg)](https://gitlab.com/patatoid/boruta_auth/-/commits/master)
[![coverage report](https://gitlab.com/patatoid/boruta_auth/badges/master/coverage.svg)](https://gitlab.com/patatoid/boruta_auth/-/commits/master)
[![downloads](https://img.shields.io/hexpm/dt/boruta)](https://hex.pm/packages/boruta)

# Boruta OAuth/OpenID Connect provider core

Boruta is the core of an OAuth 2.0 and OpenID Connect provider implementing according business rules. This library also provides a generator to create phoenix controllers, views and templates to have a basic provider up and running.

As it, a provider implemented using Boruta aim to follow RFCs:
- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
- [RFC 7009 - OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
- [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)

And specification from OpenID Foundation:
- [OpenID Connect core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

This package is meant to help to bring authorization into Elixir applications. With it, you can perform part or all of authorization code, implicit, hybrid, client credentials, or resource owner password credentials grants flows. It also helps introspecting and revoking tokens.

## Documentation

Master branch documentation can be found [here](https://patatoid.gitlab.io/boruta_auth/readme.html)

Stable documentation is hosted on [hexdocs.pm](https://hexdocs.pm/boruta/api-reference.html)

## Integration example

An example of integration can be found [here](https://gitlab.com/patatoid/boruta_example), it followed the integration steps described in below guides section.

## OpenID Certification

This package has succesfully passed basic, implicit and hybrid OpenID Profiles certifications as of May 7th, 2022 for its version [2.1.2](https://hex.pm/packages/boruta/2.1.2). This certification was performed with the above sample server.

![OpenID Certification watermark](https://gitlab.com/patatoid/boruta_auth/-/raw/master/images/oid-certification-mark.png)

## Guides

Here are some guides helping the integration of OAuth/OpenID Connect in your systems:

- [Basic OAuth/OpenID Connect provider integration](guides/provider_integration.md)
- [How to create an OAuth client](guides/create_client.md)
- [Client request authorization](guides/authorize_requests.md)
- [Notes about confidential clients](guides/confidential_clients.md)
- [Notes about pkce](guides/pkce.md)

## Feedback

It is a work in progress, all feedbacks / feature requests / improvements are welcome
