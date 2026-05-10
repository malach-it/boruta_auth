defmodule Boruta.Oauth.CodeChainRequest do
  @moduledoc """
  Code chain request
  """

  @typedoc """
  Type representing a code chain request.
  """
  @type t :: %__MODULE__{
          client_id: String.t(),
          client_authentication: %{
            type: String.t(),
            value: String.t()
          },
          id_token: String.t(),
          authorization_code: String.t() | nil,
          grant_type: String.t(),
          dpop: Boruta.Dpop.t(),
          code_challenge: String.t() | nil,
          code_challenge_method: String.t() | nil
        }
  @enforce_keys [:client_id, :client_authentication, :id_token]
  defstruct client_id: nil,
            client_authentication: nil,
            id_token: nil,
            authorization_code: nil,
            grant_type: "code_chain",
            dpop: nil,
            code_challenge: nil,
            code_challenge_method: nil
end
