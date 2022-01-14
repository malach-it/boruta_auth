# Client request authorization

Once your authorization server setup done, you can deliver tokens that help __limiting access to HTTP services__. In order to do so, you can __check validity and security information of access tokens__ provided in requests. Here we will see how restrict access using a bearer token as described in [RFC](https://datatracker.ietf.org/doc/html/rfc6750).

## In a monolithic application

In a monolith, you have access to __Boruta API__ (documented [here](https://hexdocs.pm/boruta/api-reference.html)) and can directly use it in order to restrict access to endpoints. Creating a __Plug__ and add it to the __request pipeline__ would be the prefered way to perform authorization. Here is an example of basic plugs.

```elixir
def MyAppWeb.Plugs.Authorization do
  import Plug

  use MyAppWeb, :controller

  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.Scope

  def require_authenticated(conn, _opts) do
    with [authorization_header] <- get_req_header(conn, "authorization"),
         [_authorization_header, bearer] <- Regex.run(~r/Bearer (.+)/, authorization_header),
         {:ok, token} <- Authorization.AccessToken.authorize(value: bearer) do
      conn
      |> assign(:current_token, token)
      |> assign(:current_user, Accounts.get_user!(token.sub))
    else
      _ ->
        conn
        |> put_status(:unauthorized)
        |> put_view(MyAppWeb.ErrorView)
        |> render("401.json")
        |> halt()
    end
  end

  def authorize(conn, [_h | _t] = required_scopes) do
    current_scopes = Scope.split(conn.assigns[:current_token].scope)

    case Enum.empty?(required_scopes -- current_scopes) do
      true ->
        conn

      false ->
        conn
        |> put_status(:forbidden)
        |> put_view(MyAppWeb.ErrorView)
        |> render("403.json")
        |> halt()
    end
  end
end
```

Then you can invoke those plugs in your router and controllers:
```elixir
# lib/my_app_web/router.ex
...
  import MyAppWeb.Plugs.Authorization,
    only: [
      require_authenticated: 2
    ]

  pipeline :protected_api do
    plug(:accepts, ["json"])

    plug(:require_authenticated)
  end
...

# in controllers
...
  import MyAppWeb.Plugs.Authorization,
    only: [
      authorize: 2
    ]

  plug(:authorize, ["resource:read"]) when action in [:index, :show]
  plug(:authorize, ["resource:write"]) when action in [:create, :update, :delete]
...
```

## In a microservice environment

With an authorization server set up, an __introspect endpoint__ is exposed to check token validity and provide security information as described in [RFC](https://datatracker.ietf.org/doc/html/rfc7662.html). You can create your own plugs as above but instead of using Boruta API, __request the authorization server__ to get an introspected token and all information needed to perform authorization.

> Note: the grant type `introspect` must be active on the client you are performing the requests with.

Example of introspect response:
```json
{
    "active": true,
    "client_id": "6a2f41a3-c54c-fce8-32d2-0324e1c32e20",
    "exp": 1639752235,
    "iat": 1639748635,
    "iss": "https://oauth.boruta.patatoid.fr",
    "scope": "resource:read resource:write",
    "sub": "b69c4bb6-a47b-4254-9d87-cf42bb223262",
    "username": "test@test.test"
}
```
