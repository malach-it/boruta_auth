defmodule Boruta.Openid.CredentialResponse do
  @moduledoc """
  Response in case of delivrance of verifiable credential
  """

  @enforce_keys [:format, :credential]
  defstruct format: nil,
    credential: nil

  @type t :: %__MODULE__{
    format: String.t(),
    credential: String.t()
  }

  def from_tokens(%{
    access_token: _access_token
  }, _credential_params) do
    %__MODULE__{
      format: "jwt_vc_json",
      credential: ""
    }
  end
end
