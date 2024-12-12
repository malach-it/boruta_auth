defmodule Boruta.Openid.CredentialResponse do
  @moduledoc """
  Response in case of delivrance of verifiable credential
  """

  @enforce_keys [:format, :credential]
  defstruct format: nil,
    token: nil,
    credential: nil

  @type t :: %__MODULE__{
    format: String.t(),
    token: Boruta.Oauth.Token.t(),
    credential: String.t()
  }

  def from_credential(credential, token) do
    %__MODULE__{
      credential: credential.credential,
      token: token,
      format: credential.format
    }
  end
end
