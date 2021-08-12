defmodule Boruta.Oauth.ResourceOwner do
  @moduledoc """
  Oauth resource owner
  """
  defstruct sub: nil, username: nil

  @type t :: %__MODULE__{
    sub: String.t(),
    username: String.t() | nil
  }
end
