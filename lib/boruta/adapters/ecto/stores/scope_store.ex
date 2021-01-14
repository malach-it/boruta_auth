defmodule Boruta.Ecto.ScopeStore do
  @moduledoc false

  import Boruta.Config, only: [cache_backend: 0]

  alias Boruta.Oauth.Scope

  @spec get(:public) :: {:ok, list(Scope.t())} | {:error, String.t()}
  def get(:public) do
    case cache_backend().get({Scope, :public}) do
      nil -> {:error, "Scopes not cached."}
      scopes -> {:ok, scopes}
    end
  end

  @spec invalidate(:public) :: :ok
  def invalidate(:public) do
    cache_backend().delete({Scope, :public})
  end

  @spec put_public(list(Scope.t())) :: list(Scope.t()) | {:error, reason :: String.t()}
  def put_public(scopes) do
    with :ok <- cache_backend().put({Scope, :public}, scopes) do
      scopes
    end
  end
end
