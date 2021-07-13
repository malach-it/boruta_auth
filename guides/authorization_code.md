# Authorization code grant

As stated in OAuth 2.0 RFC [Authorization code grant](https://tools.ietf.org/html/rfc6749#section-4.1) is a secure flow (recommanded) involving user agent and client in order to get access tokens.

```
                    +----------+
                    | Resource |
                    |   Owner  |
                    |          |
                    +----------+
                         ^
                         |
                        (B)
                    +----|-----+          Client Identifier      +---------------+
                    |         -+----(A)-- & Redirection URI ---->|               |
                    |  User-   |                                 | Authorization |
                    |  Agent  -+----(B)-- User authenticates --->|     Server    |
                    |          |                                 |               |
                    |         -+----(C)-- Authorization Code ---<|               |
                    +-|----|---+                                 +---------------+
                      |    |                                         ^      v
                     (A)  (C)                                        |      |
                      |    |                                         |      |
                      ^    v                                         |      |
                    +---------+                                      |      |
                    |         |>---(D)-- Authorization Code ---------'      |
                    |  Client |          & Redirection URI                  |
                    |         |                                             |
                    |         |<---(E)----- Access Token -------------------'
                    +---------+       (w/ Optional Refresh Token)
```
(A)  The client initiates the flow by directing the resource owner's user-agent to the authorization endpoint.  The client includes its client identifier, requested scope, local state, and a redirection URI to which the authorization server will send the user-agent back once access is granted (or denied).

(B)  The authorization server authenticates the resource owner (via the user-agent) and establishes whether the resource owner grants or denies the client's access request.

(C)  Assuming the resource owner grants access, the authorization server redirects the user-agent back to the client using the redirection URI provided earlier (in the request or during client registration).  The redirection URI includes an authorization code and any local state provided by the client earlier.

(D)  The client requests an access token from the authorization server's token endpoint by including the authorization code received in the previous step.  When making the request, the client authenticates with the authorization server.  The client includes the redirection URI used to obtain the authorization code for verification.

(E)  The authorization server authenticates the client, validates the authorization code, and ensures that the redirection URI received matches the URI used to redirect the client in step (C).  If valid, the authorization server responds back with an access token and, optionally, a refresh token.

> Copyright (c) 2012 IETF Trust and the persons identified as authors of the code. All rights reserved.
>
> Redistribution and use in source and binary forms, with or without modification, is permitted pursuant to, and subject to the license terms contained in, the Simplified BSD License set forth in Section 4.c of the IETF Trust’s Legal Provisions Relating to IETF Documents (http://trustee.ietf.org/license-info).

## Integration
### Code example
- lib/my_app_web/resource_owners.ex

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

- lib/my_app_web/views/oauth_view.ex


```elixir
defmodule MyAppWeb.OauthView do
  use MyAppWeb, :view

  alias Boruta.Oauth.TokenResponse

  def render("token.json", %{
    response: %TokenResponse{
        token_type: token_type,
        access_token: access_token,
        expires_in: expires_in,
        refresh_token: refresh_token
      }
  }) do
    %{
      token_type: token_type,
      access_token: access_token,
      expires_in: expires_in,
      refresh_token: refresh_token
    }
  end

  def render("error.json", %{error: error, error_description: error_description}) do
    %{
      error: error,
      error_description: error_description
    }
  end
end
```

- lib/my_app_web/templates/oauth/error.html.eex

```html
<h1><%= @error %> - An error occured while authorizing request, check client OAuth configuration</h1>
<p><%= @error_description %></p>
```

- lib/my_app_web/controllers/oauth_controller.ex

```elixir
defmodule MyAppWeb.OauthController do
  @behaviour Boruta.Oauth.Application

  use MyAppWeb, :controller

  alias Boruta.Oauth
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.TokenResponse
  alias MyAppWeb.OauthView

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

  def authorize(%Plug.Conn{query_params: query_params} = conn, _params) do
    current_user = conn.assigns[:current_user]

    conn = store_user_return_to(conn, query_params)

    Oauth.authorize(
      %ResourceOwner{sub: current_user.id, username: current_user.email},
      conn,
      __MODULE__
    )
  end

  @impl Boruta.Oauth.Application
  def authorize_success(
        conn,
        %AuthorizeResponse{
          type: type,
          redirect_uri: redirect_uri,
          code: code,
          expires_in: expires_in,
          state: state
        }
      ) do
    query_string =
      case state do
        nil ->
          URI.encode_query(%{"code" => code, "expires_in" => expires_in})

        state ->
          URI.encode_query(%{"code" => code, "expires_in" => expires_in, "state" => state})
      end

    url = "#{redirect_uri}?#{query_string}"

    redirect(conn, external: url)
  end

  @impl Boruta.Oauth.Application
  def authorize_error(
        conn,
        %Error{status: :unauthorized, error: :invalid_resource_owner}
      ) do
    # NOTE after siging in the user shall be redirected to `get_session(conn, :user_return_to)`
    redirect(conn, to: Routes.user_session_path(:new))
  end

  def authorize_error(
        conn,
        %Error{
          error: error,
          error_description: error_description,
          format: format,
          redirect_uri: redirect_uri
        }
  ) do

    query_string = URI.encode_query(%{error: error, error_description: error_description})

    case format do
      :query ->
        url = "#{redirect_uri}?#{query_string}"
        redirect(conn, external: url)
      :fragment ->
        url = "#{redirect_uri}##{query_string}"
        redirect(conn, external: url)
      _ ->
        conn
        |> put_status(status)
        |> put_view(MyAppWeb.OauthView)
        |> render("error.html", error: error, error_description: error_description)
    end
  end

  defp store_user_return_to(conn, params) do
    conn
    |> put_session(
      :user_return_to,
      Routes.oauth_path(conn, :authorize,
        client_id: params["client_id"],
        redirect_uri: params["redirect_uri"],
        response_type: params["response_type"],
        scope: params["scope"],
        state: params["state"]
      )
    )
  end
end
```

- lib/my_app_web/router.ex

```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_flash
    plug :put_secure_browser_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/oauth", MyAppWeb do
    pipe_through :api

    post "/token", OauthController, :token
  end

  scope "/oauth", MyAppWeb do
    pipe_through [
      :browser,
      :fetch_current_user # Out of OAuth scope, shall assign current_user to conn
    ]

    get "/authorize", OauthController, :authorize
  end
end
```
