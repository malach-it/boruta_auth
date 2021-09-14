defmodule Boruta.Ecto.ClientStore do
  @moduledoc false

  import Boruta.Config, only: [cache_backend: 0]

  alias Boruta.Ecto.Clients
  alias Boruta.Oauth.Client

  @spec get([id: String.t()] | [id: String.t(), secret: String.t()] | [id: String.t(), redirect_uri: String.t()]) ::
          {:ok, token :: Boruta.Oauth.Client.t()} | {:error, reason :: String.t()}
  def get(id: id) do
    case get_by_id(id) do
      %Client{} = client -> {:ok, client}
      nil -> {:error, "Client not cached."}
      error -> error
    end
  end
  def get(id: id, secret: secret) do
    with %Client{} = client <- get_by_id(id),
         :ok <- Clients.check_secret(client, secret) do
      {:ok, client}
    else
      nil -> {:error, "Client not cached."}
      error -> error
    end
  end

  def get(id: id, redirect_uri: redirect_uri) do
    with %Client{} = client <- get_by_id(id),
         :ok <- Clients.check_redirect_uri(client, redirect_uri) do
      {:ok, client}
    else
      nil -> {:error, "Client not cached."}
      error -> error
    end
  end

  defp get_by_id(id) do
    cache_backend().get({Client, id})
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

  @spec invalidate(client :: %Client{}) :: :ok
  def invalidate(client) do
    cache_backend().delete({Client, client.id})
  end
end
