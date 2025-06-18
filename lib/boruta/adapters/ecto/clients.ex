defmodule Boruta.Ecto.Clients do
  @moduledoc false

  @behaviour Boruta.Oauth.Clients
  @behaviour Boruta.Openid.Clients

  import Boruta.Config, only: [repo: 0, issuer: 0]
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]
  import Ecto.Query

  alias Boruta.Ecto.Client
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
    with {:ok, id} <- Ecto.UUID.cast(id),
         %Client{} = client <- repo().get_by(Client, id: id),
         {:ok, client} <- client |> to_oauth_schema() |> ClientStore.put() do
      client
    else
      _ -> nil
    end
  end

  # TODO implement
  @impl Boruta.Oauth.Clients
  def get_client_by_did(_did) do
    public!()
  end

  @impl Boruta.Oauth.Clients
  def public! do
    case public!(:from_cache) do
      {:ok, client} -> client
      {:error, _reason} -> public!(:from_database)
    end
  end

  defp public!(:from_cache), do: ClientStore.get_public()

  defp public!(:from_database) do
    issuer = issuer()

    with %Client{} = client <-
           repo().one(from c in Client, where: c.public_client_id == ^issuer, limit: 1),
         {:ok, client} <- client |> to_oauth_schema() |> ClientStore.put_public() do
      client
    end
  end

  def invalidate(client) do
    ClientStore.invalidate(client)
  end

  def invalidate_public do
    ClientStore.invalidate_public()
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
    clients = repo().all(Client)

    Enum.map(clients, fn client -> {client |> to_oauth_schema(), rsa_key(client)} end)
    |> Enum.uniq_by(fn {_client, %{"kid" => kid}} -> kid end)
  end

  @impl Boruta.Openid.Clients
  def create_client(registration_params) do
    with {:ok, client} <-
           %Client{}
           |> Client.create_changeset(registration_params)
           |> repo().insert() do
      client |> to_oauth_schema() |> ClientStore.put()
    end
  end

  @impl Boruta.Openid.Clients
  def refresh_jwk_from_jwks_uri(client_id) do
    with %Client{jwks_uri: "" <> jwks_uri} = client <-
           repo().get_by(Client, id: client_id),
         %URI{scheme: "" <> _scheme} <- URI.parse(jwks_uri),
         {:ok, %Finch.Response{body: jwks, status: 200}} <-
           Finch.build(:get, jwks_uri) |> Finch.request(OpenIDHttpClient),
         {:ok, %{"keys" => [jwk]}} <- Jason.decode(jwks, keys: :strings),
         {:ok, %Client{jwt_public_key: jwt_public_key}} <-
           Client.update_changeset(client, %{
             jwk: jwk,
             token_endpoint_jwt_auth_alg: jwk["alg"]
           })
           |> repo().update() do
      {:ok, jwt_public_key}
    else
      _ ->
        {:error, "Could not refresh client jwk with jwks_uri."}
    end
  end

  defp authorized_scopes(:from_database, %Oauth.Client{id: id}) do
    case repo().get_by(Client, id: id) do
      %Client{} = client ->
        {:ok, client} = to_oauth_schema(client) |> ClientStore.put()
        client.authorized_scopes

      nil ->
        []
    end
  end

  defp rsa_key(%Client{public_key: public_key, private_key: private_key}) do
    {_type, jwk} = public_key |> :jose_jwk.from_pem() |> :jose_jwk.to_map()

    Map.put(jwk, "kid", Oauth.Client.Crypto.kid_from_private_key(private_key))
  end
end
