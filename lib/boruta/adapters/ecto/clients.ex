defmodule Boruta.Ecto.Clients do
  @moduledoc false

  @behaviour Boruta.Oauth.Clients
  @behaviour Boruta.Openid.Clients

  import Boruta.Config, only: [repo: 0]
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  alias Boruta.Ecto
  alias Boruta.Ecto.ClientStore
  alias Boruta.Oauth

  @impl Boruta.Oauth.Clients
  def get_client(id) do
    case get_client(:from_cache, id) do
      {:ok, client} -> client
      {:error, _reason} -> get_client(:from_database, id)
    end
  end

  defp get_client(:from_cache, id), do: ClientStore.get_client(id)

  defp get_client(:from_database, id) do
    with %Ecto.Client{} = client <- repo().get_by(Ecto.Client, id: id),
         {:ok, client} <- client |> to_oauth_schema() |> ClientStore.put() do
      client
    end
  end

  def invalidate(client) do
    ClientStore.invalidate(client)
  end

  @impl Boruta.Oauth.Clients
  def authorized_scopes(client) do
    case ClientStore.authorized_scopes(client) do
      {:ok, authorized_scopes} -> authorized_scopes
      {:error, _reason} -> authorized_scopes(:from_database, client)
    end
  end

  @impl Boruta.Oauth.Clients
  def list_clients_jwk do
    clients = repo().all(Ecto.Client)

    Enum.map(clients, &rsa_key/1)
  end

  @impl Boruta.Openid.Clients
  def create_client(registration_params) do
    with {:ok, client} <-
           %Ecto.Client{}
           |> Ecto.Client.create_changeset(registration_params)
           |> repo().insert() do
      client |> to_oauth_schema() |> ClientStore.put()
    end
  end

  defp authorized_scopes(:from_database, %Oauth.Client{id: id}) do
    case repo().get_by(Ecto.Client, id: id) do
      %Ecto.Client{} = client ->
        {:ok, client} = to_oauth_schema(client) |> ClientStore.put()
        client.authorized_scopes

      nil ->
        []
    end
  end

  defp rsa_key(%Ecto.Client{id: client_id, public_key: public_key}) do
    {_type, jwk} = public_key |> :jose_jwk.from_pem() |> :jose_jwk.to_map()

    Map.put(jwk, "kid", client_id)
  end
end
