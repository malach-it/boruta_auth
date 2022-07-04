defmodule Boruta.Ecto.ScopeStore do
  @moduledoc false

  import Boruta.Config, only: [cache_backend: 0]

  alias Boruta.Oauth.Scope

  @spec get(:public | :all) :: {:ok, list(Scope.t())} | {:error, String.t()}
  def get(target) do
    case cache_backend().get({Scope, target}) do
      nil -> {:error, "Scopes not cached."}
      scopes -> {:ok, scopes}
    end
  end

  @spec invalidate(:public | :all) :: :ok
  def invalidate(:public) do
    cache_backend().delete({Scope, :public})
  end

  def invalidate(:all) do
    cache_backend().delete({Scope, :public})
    cache_backend().delete({Scope, :all})
  end

  @spec put_public(list(Scope.t())) :: list(Scope.t()) | {:error, reason :: String.t()}
  def put_public(scopes) do
    with :ok <- cache_backend().put({Scope, :public}, scopes) do
      scopes
    end
  end

  @spec put_all(list(Scope.t())) :: list(Scope.t()) | {:error, reason :: String.t()}
  def put_all(scopes) do
    with :ok <- cache_backend().put({Scope, :all}, scopes) do
      scopes
    end
  end
end
