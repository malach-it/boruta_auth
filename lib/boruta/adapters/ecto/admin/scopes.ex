defmodule Boruta.Ecto.Admin.Scopes do
  @moduledoc """
  `Boruta.Ecto.Scope` resource administration
  """

  import Ecto.Query, warn: false
  import Boruta.Config, only: [repo: 0]

  alias Boruta.Ecto.Scope
  alias Boruta.Ecto.Scopes

  @doc """
  Returns the list of scopes.

  ## Examples

      iex> list_scopes()
      [%Scope{}, ...]

  """
  def list_scopes do
    repo().all(Scope)
  end

  @doc """
  Gets a single scope.

  Raises `Ecto.NoResultsError` if the Scope does not exist.

  ## Examples

      iex> get_scope!(123)
      %Scope{}

      iex> get_scope!(456)
      ** (Ecto.NoResultsError)

  """
  def get_scope!(id), do: repo().get!(Scope, id)

  @doc """
  Return scopes corresponding to the given ids.

  ## Examples

      iex> get_scopes_by_ids(["9864decf-8aa4-4387-a7e4-19d1a059c912", "7b6ec16d-ad8f-4332-ac55-559184ec0f51"])
      [%Scope{}, ...]

  """
  def get_scopes_by_ids(ids), do: repo().all(from s in Scope, where: s.id in ^ids)

  @doc """
  Return scopes corresponding to the given names.

  ## Examples

      iex> get_scopes_by_names(["first:scope", "second:scope"])
      [%Scope{}, ...]

  """
  def get_scopes_by_names(names), do: repo().all(from s in Scope, where: s.name in ^names)

  @doc """
  Creates a scope.

  ## Examples

      iex> create_scope(%{field: value})
      {:ok, %Scope{}}

      iex> create_scope(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_scope(attrs \\ %{}) do
    with {:ok, scope} <- %Scope{} |> Scope.changeset(attrs) |> repo().insert(),
         :ok <- Scopes.invalidate(:public) do
      {:ok, scope}
    end
  end

  @doc """
  Updates a scope.

  ## Examples

      iex> update_scope(scope, %{field: new_value})
      {:ok, %Scope{}}

      iex> update_scope(scope, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_scope(%Scope{} = scope, attrs) do
    with {:ok, scope} <- scope |> Scope.changeset(attrs) |> repo().update(),
         :ok <- Scopes.invalidate(:public) do
      {:ok, scope}
    end
  end

  @doc """
  Deletes a Scope.

  ## Examples

      iex> delete_scope(scope)
      {:ok, %Scope{}}

      iex> delete_scope(scope)
      {:error, %Ecto.Changeset{}}

  """
  def delete_scope(%Scope{} = scope) do
    with :ok <- Scopes.invalidate(:public) do
      repo().delete(scope)
    end
  end
end
