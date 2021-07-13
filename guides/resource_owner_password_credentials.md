# Resource Owner Password Credentials grant

As stated in OAuth 2.0 RFC [Resource owner password credentials grant](https://tools.ietf.org/html/rfc6749#section-4.3) is a flow issuing access tokens for a resource owner by providing its credentials.

```
                    +----------+
                    | Resource |
                    |  Owner   |
                    |          |
                    +----------+
                         v
                         |    Resource Owner
                        (A) Password Credentials
                         |
                         v
                    +---------+                                  +---------------+
                    |         |>--(B)---- Resource Owner ------->|               |
                    |         |         Password Credentials     | Authorization |
                    | Client  |                                  |     Server    |
                    |         |<--(C)---- Access Token ---------<|               |
                    |         |    (w/ Optional Refresh Token)   |               |
                    +---------+                                  +---------------+
```
(A)  The resource owner provides the client with its username and password.

(B)  The client requests an access token from the authorization server's token endpoint by including the credentials received from the resource owner.  When making the request, the client authenticates with the authorization server.

(C)  The authorization server authenticates the client and validates the resource owner credentials, and if valid, issues an access token.

> Copyright (c) 2012 IETF Trust and the persons identified as authors of the code. All rights reserved.
>
> Redistribution and use in source and binary forms, with or without modification, is permitted pursuant to, and subject to the license terms contained in, the Simplified BSD License set forth in Section 4.c of the IETF Trust’s Legal Provisions Relating to IETF Documents (http://trustee.ietf.org/license-info).

## Integration
### Code example
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
end
```

- lib/my_app_web/router.ex

```elixir
defmodule MyAppWeb.Router do
  use MyAppWeb, :router

  pipeline :api do
    plug :accepts, ["json"]
  end

  scope "/oauth", MyAppWeb do
    pipe_through :api

    post "/token", OauthController, :token
  end
end
```
