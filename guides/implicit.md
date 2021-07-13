# Implicit grant

As stated in OAuth 2.0 RFC [Implicit grant](https://tools.ietf.org/html/rfc6749#section-4.2) is a flow suitable for javascript applications, ensuring client validity with its provided TLS certificate.

```
                    +----------+
                    | Resource |
                    |  Owner   |
                    |          |
                    +----------+
                         ^
                         |
                        (B)
                    +----|-----+          Client Identifier     +---------------+
                    |         -+----(A)-- & Redirection URI --->|               |
                    |  User-   |                                | Authorization |
                    |  Agent  -|----(B)-- User authenticates -->|     Server    |
                    |          |                                |               |
                    |          |<---(C)--- Redirection URI ----<|               |
                    |          |          with Access Token     +---------------+
                    |          |            in Fragment
                    |          |                                +---------------+
                    |          |----(D)--- Redirection URI ---->|   Web-Hosted  |
                    |          |          without Fragment      |     Client    |
                    |          |                                |    Resource   |
                    |     (F)  |<---(E)------- Script ---------<|               |
                    |          |                                +---------------+
                    +-|--------+
                      |    |
                     (A)  (G) Access Token
                      |    |
                      ^    v
                    +---------+
                    |         |
                    |  Client |
                    |         |
                    +---------+
```
(A)  The client initiates the flow by directing the resource owner's user-agent to the authorization endpoint.  The client includes its client identifier, requested scope, local state, and a redirection URI to which the authorization server will send the user-agent back once access is granted (or denied).

(B)  The authorization server authenticates the resource owner (via the user-agent) and establishes whether the resource owner grants or denies the client's access request.

(C)  Assuming the resource owner grants access, the authorization server redirects the user-agent back to the client using the redirection URI provided earlier.  The redirection URI includes the access token in the URI fragment.

(D)  The user-agent follows the redirection instructions by making a request to the web-hosted client resource (which does not include the fragment per [RFC2616]).  The user-agent retains the fragment information locally.

(E)  The web-hosted client resource returns a web page (typically an HTML document with an embedded script) capable of accessing the full redirection URI including the fragment retained by the user-agent, and extracting the access token (and other parameters) contained in the fragment.

(F)  The user-agent executes the script provided by the web-hosted client resource locally, which extracts the access token.

(G)  The user-agent passes the access token to the client.

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
  alias MyAppWeb.OauthView

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
          access_token: access_token,
          expires_in: expires_in,
          state: state
        }
      ) do
    query = URI.encode_query(%{"access_token" => access_token, "expires_in" => expires_in})

    url = "#{redirect_uri}##{query_string}"

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

  scope "/oauth", MyAppWeb do
    pipe_through [
      :browser,
      :fetch_current_user # Out of OAuth scope, shall assign current_user to conn
    ]

    get "/authorize", OauthController, :authorize
  end
end
```
