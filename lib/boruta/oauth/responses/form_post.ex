defmodule Boruta.Oauth.FormPostResponse do
  @moduledoc """
  Response returned when `response_mode=form_post` is requested.

  As defined in [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html),
  this response contains the authorization parameters that should be delivered to the client
  via an HTML form that auto-submits via HTTP POST.

  The application layer is responsible for rendering an HTML page with a self-submitting form.
  The form should:
  - Have `action` set to `redirect_uri`
  - Have `method` set to "POST"
  - Include each parameter as a hidden input field
  - Auto-submit using JavaScript (e.g., `onload="document.forms[0].submit()"`)

  ## Content Security Policy

  When serving the form_post response, you should include a Content-Security-Policy header
  with the `form-action` directive to restrict where the form can be submitted. This prevents
  potential attackers from injecting forms that submit to malicious endpoints.

  The `form-action` directive should be set to the client's `redirect_uri`:

      Content-Security-Policy: form-action https://client.example.com/callback

  ## Example Phoenix Controller

  ```elixir
  def form_post_success(conn, %FormPostResponse{} = response) do
    conn
    |> put_resp_header(
      "content-security-policy",
      "form-action \#{response.redirect_uri}"
    )
    |> put_resp_header("x-frame-options", "DENY")
    |> put_resp_header("cache-control", "no-store")
    |> put_resp_header("pragma", "no-cache")
    |> put_view(MyAppWeb.OauthView)
    |> render("form_post.html", response: response)
  end
  ```

  ## Example HEEx Template (Phoenix 1.7+)

  ```heex
  <html>
    <head><title>Submitting...</title></head>
    <body onload="document.forms[0].submit()">
      <form method="POST" action={@response.redirect_uri}>
        <input
          :for={{name, value} <- FormPostResponse.params(@response)}
          type="hidden"
          name={name}
          value={value}
        />
        <noscript>
          <p>JavaScript is disabled. Click the button below to continue.</p>
          <input type="submit" value="Continue" />
        </noscript>
      </form>
    </body>
  </html>
  ```
  """

  @enforce_keys [:redirect_uri]
  defstruct redirect_uri: nil,
            access_token: nil,
            code: nil,
            expires_in: nil,
            id_token: nil,
            state: nil,
            token_type: nil,
            type: nil

  @type t :: %__MODULE__{
          redirect_uri: String.t(),
          access_token: String.t() | nil,
          code: String.t() | nil,
          expires_in: integer() | nil,
          id_token: String.t() | nil,
          state: String.t() | nil,
          token_type: String.t() | nil,
          type: :token | :code | :hybrid
        }

  @doc """
  Returns the response parameters as a map suitable for form fields.

  Only includes non-nil values.
  """
  @spec params(t()) :: %{atom() => String.t() | integer()}
  def params(%__MODULE__{} = response) do
    %{
      code: response.code,
      id_token: response.id_token,
      access_token: response.access_token,
      expires_in: response.expires_in,
      state: response.state,
      token_type: response.token_type
    }
    |> Enum.filter(fn {_key, value} -> not is_nil(value) end)
    |> Enum.into(%{})
  end
end
