defmodule Boruta.Ecto.Admin.Tokens do
  @moduledoc """
  `Boruta.Ecto.Token` resource administration.
  """

  import Boruta.Config, only: [repo: 0]
  import Ecto.Query, warn: false

  alias Boruta.Ecto.Token

  @doc """
  Returns a query requesting all active tokens given `Ecto.Queryable` (defaults to all).

  ## Examples

      iex> list_active_tokens()
      [%Token{}, ...]

  """
  @spec list_active_tokens() :: Ecto.Queryable.t()
  @spec list_active_tokens(queryable :: Ecto.Queryable.t()) :: Ecto.Queryable.t()
  def list_active_tokens(queryable \\ Token) do
    now = :os.system_time(:seconds)
    queryable
    |> where([t], t.expires_at >= ^now)
    |> where([t], is_nil(t.revoked_at))
    |> repo().all()
  end
end
