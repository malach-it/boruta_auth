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
Documentation can be found [here](https://patatoid.gitlab.io/boruta_auth/Boruta.html)

## Live example
A live example can be found [here](http://oauth.boruta.patatoid.fr/)

## Installation
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
  repo: MyApp.Repo,
  cache_backend: Boruta.Cache,
  contexts: [
    access_tokens: Boruta.Ecto.AccessTokens,
    clients: Boruta.Ecto.Clients,
    codes: Boruta.Ecto.Codes,
    resource_owners: MyApp.ResourceOwners,
    scopes: Boruta.Ecto.Scopes
  ],
  max_ttl: [
    authorization_code: 60,
    access_token: 60 * 60 * 24
  ],
  token_generator: Boruta.TokenGenerator
```

## Integration
This implementation follows a pseudo hexagonal architecture to invert dependencies to Application layer.
In order to expose endpoints of an OAuth server with Boruta, you need implement the behaviour `Boruta.Oauth.Application` with all needed callbacks for `token/2`, `authorize/2` and `introspect/2` calls from `Boruta.Oauth`.

This library has specific interfaces to interact with `Plug.Conn` requests.

Here is an example of a token endpoint controller:
```elixir
defmodule MyApp.OauthController do
  @behaviour Boruta.Oauth.Application
  ...
  def token(%Plug.Conn{} = conn, _params) do
    conn |> Oauth.token(__MODULE__)
  end

  @impl Boruta.Oauth.Application
  def token_success(conn, %TokenResponse{} = response) do
    conn
    |> put_view(OauthView)
    |> render("token.json", response: response)
  end

  @impl Boruta.Oauth.Application
  def token_error(conn, %Error{status: status, error: error, error_description: error_description}) do
    conn
    |> put_status(status)
    |> put_view(OauthView)
    |> render("error.json", error: error, error_description: error_description)
  end
  ...
end
```

## Create an OAuth client
You can also create a client and test it
```
# create a client
{:ok, %Boruta.Ecto.Client{id: client_id, secret: client_secret}} = Boruta.Ecto.Admin.create_client(%{authorization_code_ttl: 60, access_token_ttl: 60 * 60})
# obtain a token
{:ok, %Boruta.Oauth.Token{value: value}} = Boruta.Oauth.Authorization.token(%Boruta.Oauth.ClientCredentialsRequest{client_id: client_id, client_secret: client_secret})
# check token
{:ok, _token} = Boruta.Oauth.Authorization.AccessToken.authorize(value: value)
```

## Feedback
It is a work in progress, all feedbacks / feature requests / improvements are welcome
