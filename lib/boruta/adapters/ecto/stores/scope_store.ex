defmodule Boruta.Ecto.ScopeStore do
  @moduledoc false

  alias Boruta.Cache
  alias Boruta.Oauth.Scope

  @spec get(:public) :: {:ok, list(Scope.t())} | {:error, String.t()}
  def get(:public) do
    case Cache.get({Scope, :public}) do
      nil -> {:error, "Scopes not cached."}
      scopes -> {:ok, scopes}
    end
  end

  @spec invalidate(:public) :: :ok
  def invalidate(:public) do
    Cache.delete{Scope, :public}
  end

  @spec put_public(list(Scope.t())) :: list(Scope.t()) | {:error, reason :: String.t()}
  def put_public(scopes) do
    with :ok <- Cache.put({Scope, :public}, scopes) do
      scopes
    end
  end
end
