defmodule Boruta.Ecto.Admin.Tokens do
  @moduledoc """
  `Boruta.Ecto.Token` resource administration
  """

  import Boruta.Config, only: [repo: 0]
  import Ecto.Query, warn: false

  alias Boruta.Ecto.Token

  @doc """
  Returns all active tokens given `Ecto.Queryable` (defaults to all).

  ## Examples

      iex> list_active_tokens()
      [%Token{}, ...]

  """
  @spec list_active_tokens() :: active_tokens :: list(Token.t())
  @spec list_active_tokens(queryable :: Ecto.Queryable.t()) :: active_tokens :: list(Token.t())
  def list_active_tokens(queryable \\ Token) do
    queryable
    |> active_tokens_query()
    |> repo().all()
  end

  @spec delete_inactive_tokens() ::
          {number_of_deleted_tokens :: integer(), nil}
  @spec delete_inactive_tokens(until :: DateTime.t()) ::
          {number_of_deleted_tokens :: integer(), nil}
  def delete_inactive_tokens(until \\ DateTime.utc_now()) do
    until = DateTime.to_unix(until)
    from(t in Token, as: :parent)
    |> where([t], t.expires_at < ^until)
    |> where(
      [parent: t],
      not exists(active_tokens_query() |> where([t], parent_as(:parent).id == t.id))
    )
    |> repo().delete_all()
  end

  defp active_tokens_query(queryable \\ Token) do
    now = :os.system_time(:seconds)

    queryable
    |> where([t], t.expires_at >= ^now)
    |> where([t], is_nil(t.revoked_at))
  end
end
