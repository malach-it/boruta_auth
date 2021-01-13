defmodule Boruta.Ecto.ClientStore do
  @moduledoc false

  alias Boruta.Cache
  alias Boruta.Oauth.Client

  @spec get([id: String.t(), secret: String.t()] | [id: String.t(), redirect_uri: String.t()]) ::
    {:ok, token :: Boruta.Oauth.Client.t()} | {:error, reason :: String.t()}
  def get(id: id, secret: secret) do
    with %Client{secret: client_secret} = client <- get_by_id(id),
      # TODO move logic to Clients
      true <- secret == client_secret do
        {:ok, client}
      else
        false -> {:error, "Client secret do not match."}
        nil -> {:error, "Client not cached."}
    end
  end
  def get(id: id, redirect_uri: redirect_uri) do
    with %Client{redirect_uris: client_redirect_uris} = client <- get_by_id(id),
      # TODO move logic to Clients
      true <- Enum.member?(client_redirect_uris, redirect_uri) do
        {:ok, client}
      else
        false -> {:error, "Client redirect_uri do not match."}
        nil -> {:error, "Client not cached."}
    end
  end

  defp get_by_id(id) do
    Cache.get({Client, id})
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
    with :ok <- Cache.put({Client, client.id}, client) do
      {:ok, client}
    end
  end

  @spec invalidate(client :: %Client{}) :: :ok
  def invalidate(client) do
    Cache.delete({Client, client.id})
  end
end
