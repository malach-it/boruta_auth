defmodule Boruta.Oauth.ClientCredentialsRequest do
  @moduledoc """
  Client credentials request
  """

  @typedoc """
  Type representing a client credentials request as stated in [OAuth 2.0 RFC](https://tools.ietf.org/html/rfc6749#section-4.4.2).
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          client_secret: String.t(),
          scope: String.t(),
          grant_type: String.t()
        }
  @enforce_keys [:client_id, :client_secret]
  defstruct client_id: nil, client_secret: nil, scope: "", grant_type: "client_credentials"
end
