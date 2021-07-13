# Hybrid flow

As stated in OpenID Connect core 1.0 [Hybrid flow](https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth) is a flow based on Authorization code grant flow.

See [Authorization Code grant](authorization_code.md) for the flow steps aknowledgement.

The major difference with authorization code grant is the possible addition of response types `id_token` and `token` while requesting for a code.

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

  @impl Boruta.Oauth.ResourceOwners
  def claims(sub) do
    with %User{email: email} = user <- Repo.get_by(User, id: sub) do
      %{"email" => email}
    end
  end
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
          id_token: id_token,
          access_token: access_token,
          expires_in: expires_in,
          state: state
        }
      ) do
    query =
      %{
        code: code,
        id_token: id_token,
        access_token: access_token,
        expires_in: expires_in,
        state: state
      }
      |> Enum.flat_map(fn
        {_param_type, nil} -> []
        pair -> [pair]
      end)
      |> URI.encode_query()

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
