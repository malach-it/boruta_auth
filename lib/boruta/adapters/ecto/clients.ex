defmodule Boruta.Ecto.Clients do
  @moduledoc false

  @behaviour Boruta.Oauth.Clients

  import Ecto.Query, only: [from: 2]
  import Boruta.Config, only: [repo: 0]
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  alias Boruta.Ecto
  alias Boruta.Ecto.ClientStore
  alias Boruta.Oauth

  @impl Boruta.Oauth.Clients
  def get_by(attrs) do
    case get_by(:from_cache, attrs) do
      {:ok, client} -> client
      {:error, _reason} -> get_by(:from_database, attrs)
    end
  end

  defp get_by(:from_cache, attrs), do: ClientStore.get(attrs)
  defp get_by(:from_database, id: id) do
    with %Ecto.Client{} = client <- repo().get_by(Ecto.Client, id: id),
      {:ok, client} <- to_oauth_schema(client) |> ClientStore.put() do
        client
    end
  end
  defp get_by(:from_database, id: id, secret: secret) do
    with %Ecto.Client{} = client <- repo().get_by(Ecto.Client, id: id, secret: secret),
      {:ok, client} <- to_oauth_schema(client) |> ClientStore.put() do
        client
    end
  end
  defp get_by(:from_database, id: id, redirect_uri: redirect_uri) do
    with %Ecto.Client{} = client <-
           repo().one(
             from c in Ecto.Client,
               where:
                 c.id == ^id and
                   ^redirect_uri in c.redirect_uris
           ),
      {:ok, client} <- to_oauth_schema(client) |> ClientStore.put() do
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

  defp authorized_scopes(:from_database, %Oauth.Client{id: id}) do
    case repo().get_by(Ecto.Client, id: id) do
      %Ecto.Client{} = client ->
        {:ok, client} = to_oauth_schema(client) |> ClientStore.put()
        client.authorized_scopes
      nil ->
        []
    end
  end

  @spec check_secret(client :: Oauth.Client.t(), secret :: String.t()) ::
    :ok | {:error, String.t()}
  def check_secret(%Oauth.Client{secret: client_secret}, secret) do
    case client_secret == secret do
      true -> :ok
      false -> {:error, "Client secret do not match."}
    end
  end

  @spec check_redirect_uri(client :: Oauth.Client.t(), redirect_uri :: String.t()) ::
    :ok | {:error, String.t()}
  def check_redirect_uri(%Oauth.Client{redirect_uris: client_redirect_uris}, redirect_uri) do
    case Enum.member?(client_redirect_uris, redirect_uri) do
      true -> :ok
      false -> {:error, "Client redirect_uri do not match."}
    end
  end
end
