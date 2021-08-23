defmodule Boruta.Oauth.RefreshTokenRequest do
  @moduledoc """
  Refresh token request
  """

  @typedoc """
  Type representing a refresh token request as stated in [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749#section-1.5).
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          client_secret: String.t(),
          refresh_token: String.t(),
          scope: String.t(),
          grant_type: String.t()
        }
  @enforce_keys [:client_id, :client_secret, :refresh_token]
  defstruct client_id: nil,
            client_secret: nil,
            refresh_token: nil,
            scope: "",
            grant_type: "refresh_token"
end
