defmodule Boruta.Internal.Signatures.SigningKey do
  @moduledoc false

  @enforce_keys [:type]
  defstruct [:type, :kid, :public_key, :private_key, :secret, :trust_chain]

  @type t :: %__MODULE__{
          type: :external | :internal,
          public_key: String.t() | nil,
          private_key: String.t() | nil,
          kid: String.t() | nil,
          secret: String.t() | nil,
          trust_chain: list(String.t()) | nil
        }
end
