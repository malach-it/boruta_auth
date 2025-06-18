defmodule Boruta.Openid.Credential do
  @moduledoc """
  Credentials and utilities
  """

  defstruct id: nil,
            credential: nil,
            format: nil,
            defered: nil,
            access_token: nil

  @type t :: %__MODULE__{
          id: String.t(),
          credential: String.t(),
          format: String.t(),
          defered: boolean(),
          access_token: String.t()
        }

  def persisted?(%__MODULE__{id: nil}), do: false
  def persisted?(_request), do: true
end
