defmodule Boruta.Openid.DeferedCredentialResponse do
  @moduledoc """
  Response in case of delivrance of verifiable credential
  """

  @enforce_keys [:acceptance_token]
  defstruct acceptance_token: nil,
    c_nonce: nil,
    c_nonce_expires_in: nil

  @type t :: %__MODULE__{
    acceptance_token: String.t(),
    c_nonce: String.t(),
    c_nonce_expires_in: String.t()
  }

  def from_credential(_credential, token) do
    %__MODULE__{
      acceptance_token: token.value,
      c_nonce: token.c_nonce,
      c_nonce_expires_in: token.expires_at - :os.system_time(:second)
    }
  end
end
