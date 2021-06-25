# Client credentials grant

As stated in OAuth 2.0 RFC [Client credentials grant](https://tools.ietf.org/html/rfc6749#section-4.4) is a flow involving servers in order for them to get access tokens.

```
                    +---------+                                  +---------------+
                    |         |                                  |               |
                    |         |>--(A)- Client Authentication --->| Authorization |
                    | Client  |                                  |     Server    |
                    |         |<--(B)---- Access Token ---------<|               |
                    |         |                                  |               |
                    +---------+                                  +---------------+
```
(A)  The client authenticates with the authorization server and requests an access token from the token endpoint.

(B)  The authorization server authenticates the client, and if valid, issues an access token.

> Copyright (c) 2012 IETF Trust and the persons identified as authors of the code. All rights reserved.
>
> Redistribution and use in source and binary forms, with or without modification, is permitted pursuant to, and subject to the license terms contained in, the Simplified BSD License set forth in Section 4.c of the IETF Trust’s Legal Provisions Relating to IETF Documents (http://trustee.ietf.org/license-info).

## Integration
### Code example
- lib/my_app_web/views/oauth_view.ex

```
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

```
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

```
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
