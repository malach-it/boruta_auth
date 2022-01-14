defmodule Boruta.Oauth.ResourceOwner do
  @moduledoc """
  Oauth resource owner schema
  """

  @enforce_keys [:sub]
  defstruct sub: nil, username: nil, last_login_at: nil

  @type t :: %__MODULE__{
    sub: String.t(),
    username: String.t() | nil,
    last_login_at: DateTime.t() | nil
  }
end
