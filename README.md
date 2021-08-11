[![pipeline status](https://gitlab.com/patatoid/boruta_auth/badges/master/pipeline.svg)](https://gitlab.com/patatoid/boruta_auth/-/commits/master)
[![coverage report](https://gitlab.com/patatoid/boruta_auth/badges/master/coverage.svg)](https://gitlab.com/patatoid/boruta_auth/-/commits/master)

# Boruta OAuth provider core
Boruta is the core of an OAuth provider giving business logic of authentication and authorization.

It is intended to follow RFCs:
- [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
- [RFC 7009 - OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)
- [RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients](https://tools.ietf.org/html/rfc7636)

As it, it helps implement a provider for authorization code, implicit, client credentials and resource owner password credentials grants. Then it follows Introspection to check tokens.

## Documentation
Documentation can be found [here](https://patatoid.gitlab.io/boruta_auth/readme.html)

## Live example
A live example can be found [here](http://oauth.boruta.patatoid.fr/)

## Setup
1. Schemas migration

If you plan to use Boruta builtin clients and tokens contexts, you'll need a migration for its `Ecto` schemas. This can be done by running:
```sh
mix boruta.gen.migration
```

2. Implement ResourceOwners context

In order to have user flows working, You need to implement `Boruta.Oauth.ResourceOwners`.

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
      {:ok, %ResourceOwner{sub: id, username: email}}
    else
      _ -> {:error, "User not found."}
    end
  end
  def get_by(sub: sub) do
    with %User{id: id, email: email} = user <- Repo.get_by(User, id: sub) do
      {:ok, %ResourceOwner{sub: id, username: email}}
    else
      _ -> {:error, "User not found."}
    end
  end

  @impl Boruta.Oauth.ResourceOwners
  def check_password(resource_owner, password) do
    User.check_password(user, password)
  end

  @impl Boruta.Oauth.ResourceOwners
  def authorized_scopes(%ResourceOwner{}), do: []
end
```

3. Configuration

Boruta provides several configuration options, to customize them you can add configurations in `config.exs` as following
```elixir
config :boruta, Boruta.Oauth,
  repo: MyApp.Repo, # mandatory
  cache_backend: Boruta.Cache,
  contexts: [
    access_tokens: Boruta.Ecto.AccessTokens,
    clients: Boruta.Ecto.Clients,
    codes: Boruta.Ecto.Codes,
    resource_owners: MyApp.ResourceOwners, # mandatory
    scopes: Boruta.Ecto.Scopes
  ],
  max_ttl: [
    authorization_code: 60,
    access_token: 60 * 60 * 24
  ],
  token_generator: Boruta.TokenGenerator
```

## Integration
This implementation follows an hexagonal architecture, dependencies are inverted from Application layer.

In order to expose endpoints of an OAuth server with Boruta, you need implement either the behaviour `Boruta.Oauth.Application` or the behaviours `Boruta.Oauth.AuthorizeApplication`, `Boruta.Oauth.TokenApplication`, `Boruta.Oauth.IntrospectApplication` and `Boruta.Oauth.RevokeApplication` to integrate these endpoints separatly. Those behaviours will help you creating callback functions which will be triggered by invoking `token/2`, `authorize/2`, `introspect/2` and `revoke/2` functions from `Boruta.Oauth` module.

A generator is provided to create phoenix controllers, views and templates needed to implement a basic OAuth server.

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
Some integration guides are provided with code samples.
- [Authorization code grant](authorization_code.md)
- [Client Credentials grant](client_credentials.md)
- [Implicit grant](implicit.md)
- [Resource Owner Password Credentials grant](resource_owner_password_credentials.md)
- [Introspect](introspect.md)
- [Revoke](revoke.md)

## Feedback
It is a work in progress, all feedbacks / feature requests / improvements are welcome
