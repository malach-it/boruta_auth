defmodule Boruta.Oauth.AuthorizationCodeRequest do
  @moduledoc """
  Authorization code request
  """

  @typedoc """
  Type representing an authorization code request as stated in [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749#section-4.1.3).
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          redirect_uri: String.t(),
          code: String.t(),
          grant_type: String.t(),
          code_verifier: String.t()
        }
  @enforce_keys [:client_id, :redirect_uri, :code]
  defstruct client_id: nil,
            redirect_uri: nil,
            code: nil,
            grant_type: "authorization_code",
            code_verifier: ""
end
