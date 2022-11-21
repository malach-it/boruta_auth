defmodule Boruta.Oauth.RevokeRequest do
  @moduledoc """
  Revoke request
  """

  @typedoc """
  Type representing an revoke request as stated in [OAuth 2.0 Token revocation RFC](https://tools.ietf.org/html/rfc7009#section-2.1).
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          client_authentication: %{
            type: String.t(),
            value: String.t()
          },
          token: String.t(),
          token_type_hint: String.t()
        }
  @enforce_keys [:client_id, :client_authentication, :token]
  defstruct client_id: nil, client_authentication: nil, token: nil, token_type_hint: nil
end
