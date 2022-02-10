[![pipeline status](https://gitlab.com/patatoid/boruta_auth/badges/master/pipeline.svg)](https://gitlab.com/patatoid/boruta_auth/-/commits/master)
[![coverage report](https://gitlab.com/patatoid/boruta_auth/badges/master/coverage.svg)](https://gitlab.com/patatoid/boruta_auth/-/commits/master)
[![downloads](https://img.shields.io/hexpm/dt/boruta)](https://hex.pm/packages/boruta)

# Boruta OAuth/OpenID Connect provider core
Boruta is the core of an OAuth/OpenID Connect provider giving authorization business rules. A generator is provided to create phoenix controllers, views and templates to have a basic provider up and running.

It is intended to follow RFCs:
- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
- [RFC 7009 - OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
- [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)

And specification from OpenID Connect:
- [OpenID Connect core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)


This package is meant to help to provide OAuth 2.0/OpenID Connect to your applications implementing part or all of authorization code, implicit, hybrid, client credentials, or resource owner password credentials grants. It also helps introspecting and revoking tokens.

## Documentation
Master branch documentation can be found [here](https://patatoid.gitlab.io/boruta_auth/readme.html)

Stable documentation is hosted on [hexdocs.pm](https://hexdocs.pm/boruta/api-reference.html)

## Live example
A live example can be found [here](http://oauth.boruta.patatoid.fr/)

## Integration example
An example of integration can be found [here](https://gitlab.com/patatoid/boruta_example)

## Setup
1. Schemas migration

If you plan to use Boruta builtin clients and tokens contexts, you'll need a migration for its `Ecto` schemas. This can be done by running:
```sh
mix boruta.gen.migration
```
> Note: You may need to run the task above in case of package upgrade to have up to date database schema.

2. Implement ResourceOwners context _(optional)_

In order to have user flows operational, You need to implement `Boruta.Oauth.ResourceOwners` behaviour.

Here is an example implementation:
```elixir
defmodule MyApp.ResourceOwners do
  @behaviour Boruta.Oauth.ResourceOwners

  alias Boruta.Oauth.ResourceOwner
  alias MyApp.Accounts.User
  alias MyApp.Repo

  @impl Boruta.Oauth.ResourceOwners
  def get_by(username: username) do
    with %User{id: id, email: email} <- Repo.get_by(User, email: username) do
      {:ok, %ResourceOwner{sub: to_string(id), username: email}}
    else
      _ -> {:error, "User not found."}
    end
  end
  def get_by(sub: sub) do
    with %User{id: id, email: email} <- Repo.get_by(User, id: sub) do
      {:ok, %ResourceOwner{sub: to_string(id), username: email}}
    else
      _ -> {:error, "User not found."}
    end
  end

  @impl Boruta.Oauth.ResourceOwners
  def check_password(resource_owner, password) do
    user = Repo.get_by(User, id: resource_owner.sub)
    case User.valid_password?(user, password) do
      true -> :ok
      false -> {:error, "Invalid email or password."}
    end
  end

  @impl Boruta.Oauth.ResourceOwners
  def authorized_scopes(%ResourceOwner{}), do: []
end
```

3. Configuration

Boruta provides several configuration options that you can customize in `config.exs`. Those have following default values:
```elixir
config :boruta, Boruta.Oauth,
  repo: MyApp.Repo, # mandatory
  cache_backend: Boruta.Cache,
  contexts: [
    access_tokens: Boruta.Ecto.AccessTokens,
    clients: Boruta.Ecto.Clients,
    codes: Boruta.Ecto.Codes,
    resource_owners: MyApp.ResourceOwners, # mandatory for user flows
    scopes: Boruta.Ecto.Scopes
  ],
  max_ttl: [
    authorization_code: 60,
    access_token: 60 * 60 * 24,
    id_token: 60 * 60 * 24,
    refresh_token: 60 * 60 * 24 * 30
  ],
  token_generator: Boruta.TokenGenerator,
  issuer: "boruta"
```

## Integration
This implementation follows an inverted hexagonal architecture, dependencies are inverted from Application layer.

In order to expose endpoints of an OAuth/OpenID Connect server with Boruta, you need implement either the behaviour `Boruta.Oauth.Application` or the behaviours `Boruta.Oauth.AuthorizeApplication`, `Boruta.Oauth.TokenApplication`, `Boruta.Oauth.IntrospectApplication` and `Boruta.Oauth.RevokeApplication` to integrate these endpoints separatly. Those behaviours will help you creating callback functions which will be triggered by invoking `token/2`, `authorize/2`, `introspect/2` and `revoke/2` functions from `Boruta.Oauth` module.

A generator is provided to create phoenix controllers, views and templates needed to implement a basic OAuth/OpenID Connect server.

```sh
mix boruta.gen.controllers
```

This task will create needed files and give you a guide to finish your setup.

## Straightforward testing
You can also create a client and test it
```elixir
alias Boruta.Ecto
alias Boruta.Oauth.Authorization
alias Boruta.Oauth.{ClientCredentialsRequest, Token}

# create a client
{:ok, %Ecto.Client{id: client_id, secret: client_secret}} = Ecto.Admin.create_client(%{})
# obtain a token
{:ok, %Token{value: value}} = Authorization.token(%ClientCredentialsRequest{client_id: client_id, client_secret: client_secret})
# check token
{:ok, _token} = Authorization.AccessToken.authorize(value: value)
```

## Guides

Here are some guides helping the integration of OAuth/OpenID Connect in your systems:

- [Basic OAuth/OpenID Connect provider integration](guides/provider_integration.md)
- [How to create an OAuth client](guides/create_client.md)
- [Client request authorization](guides/authorize_requests.md)
- [Notes about pkce](guides/pkce.md)

## Product

This package is part of the vision of a wider product, targetting to provide a full-featured IAM solution. [Here](https://docs.google.com/presentation/d/1seuUaICy6YHt8u29pRZa4-ocOEf5bDMts5GSTv6TMM4/edit?usp=sharing) is a presentation that aims to give a vision of the product and key steps in order to achieve the goal to bring identity to organizations empowering user privacy and control. Feel free to comment or to reach out.

## Feedback
It is a work in progress, all feedbacks / feature requests / improvements are welcome
