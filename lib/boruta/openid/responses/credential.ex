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

  def from_credential(credential) do
    struct(__MODULE__, credential)
  end
M
end
