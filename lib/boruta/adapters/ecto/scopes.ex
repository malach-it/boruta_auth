defmodule Boruta.Ecto.Scopes do
  @moduledoc false

  @behaviour Boruta.Oauth.Scopes

  import Ecto.Query, only: [from: 2]
  import Boruta.Config, only: [repo: 0]
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  alias Boruta.Ecto
  alias Boruta.Ecto.ScopeStore

  @impl Boruta.Oauth.Scopes
  def public do
    case ScopeStore.get(:public) do
      {:ok, scopes} ->
        scopes
      {:error, _reason} ->
        repo().all(
          from s in Ecto.Scope,
          where: s.public == true
        )
        |> Enum.map(&to_oauth_schema/1)
        |> ScopeStore.put_public()
    end
  end

  def all do
    case ScopeStore.get(:all) do
      {:ok, scopes} ->
        scopes
      {:error, _reason} ->
        repo().all(Ecto.Scope)
        |> Enum.map(&to_oauth_schema/1)
        |> ScopeStore.put_all()
    end
  end

  def invalidate(:public) do
    ScopeStore.invalidate(:public)
  end

  def invalidate(:all) do
    ScopeStore.invalidate(:all)
  end
end
