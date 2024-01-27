defmodule Boruta.Ecto.ClientStore do
  @moduledoc false

  import Boruta.Config, only: [cache_backend: 0]

  alias Boruta.Oauth.Client

  @spec get_client(String.t()) ::
          {:ok, token :: Boruta.Oauth.Client.t()} | {:error, reason :: String.t()}
  def get_client(id) do
    case get_by_id(id) do
      %Client{} = client -> {:ok, client}
      nil -> {:error, "Client not cached."}
    end
  end

  defp get_by_id(id) do
    cache_backend().get({Client, id})
  end

  @spec get_public() :: client :: Boruta.Oauth.Client.t()
  def get_public do
    case cache_backend().get({Client, :public}) do
      nil -> {:error, "No public client stored."}
      client -> {:ok, client}
    end
  end

  def authorized_scopes(%Client{id: id}) do
    case get_by_id(id) do
      nil -> {:error, "Client not cached."}
      %Client{} = client -> {:ok, client.authorized_scopes}
    end
  end

  @spec put(client :: Boruta.Oauth.Client.t()) ::
          {:ok, client :: Boruta.Oauth.Client.t()} | {:error, reason :: String.t()}
  def put(client) do
    with :ok <- cache_backend().put({Client, client.id}, client) do
      {:ok, client}
    end
  end

  @spec put_public(client :: Boruta.Oauth.Client.t()) ::
          {:ok, client :: Boruta.Oauth.Client.t()} | {:error, reason :: String.t()}
  def put_public(client) do
    with :ok <- cache_backend().put({Client, :public}, client) do
      {:ok, client}
    end
  end

  @spec invalidate(client :: %Client{}) :: :ok
  def invalidate(client) do
    cache_backend().delete({Client, client.id})
  end
end
