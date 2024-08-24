defmodule Boruta.Ecto.Admin.Clients do
  @moduledoc """
  `Boruta.Ecto.Client` resource administration
  """

  import Boruta.Config, only: [repo: 0]
  import Ecto.Query, warn: false

  alias Boruta.Ecto.Client
  alias Boruta.Ecto.Clients
  alias Boruta.Oauth

  @doc """
  Returns the list of clients.

  ## Examples

      iex> list_clients()
      [%Client{}, ...]

  """
  def list_clients do
    clients = repo().all(Client)

    repo().preload(clients, :authorized_scopes)
  end

  @doc """
  Gets a single client.

  Raises `Ecto.NoResultsError` if the Client does not exist.

  ## Examples

      iex> get_client!(123)
      %Client{}

      iex> get_client!(456)
      ** (Ecto.NoResultsError)

  """
  def get_client!(id) do
    client = repo().get!(Client, id)

    repo().preload(client, :authorized_scopes)
  end

  @doc """
  Creates a client.

  ## Examples

      iex> create_client(%{field: value})
      {:ok, %Client{}}

      iex> create_client(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_client(attrs) do
    %Client{}
    |> Client.create_changeset(attrs)
    |> repo().insert()
  end

  @doc """
  Regenerates client did.

  ## Examples

      iex> regenerate_client_did(client)
      {:ok, %Client{}}

  """
  def regenerate_client_did(%Client{} = client) do
    with {:ok, client} <- client |> Client.did_changeset() |> repo().update(),
         :ok <- Clients.invalidate(%Oauth.Client{id: client.id}) do
      {:ok, client}
    end
  end

  @doc """
  Regenerates client secret. If a secret is provided as parameter, updates it.

  ## Examples

      iex> regenerate_client_secret(client)
      {:ok, %Client{}}

  """
  def regenerate_client_secret(%Client{} = client, secret \\ nil) do
    with {:ok, client} <- client |> Client.secret_changeset(secret) |> repo().update(),
         :ok <- Clients.invalidate(%Oauth.Client{id: client.id}) do
      {:ok, client}
    end
  end

  @doc """
  Regenerates client key pair. If a couple public/private key is provided as parameter, updates it.

  ## Examples

      iex> regenerate_client_key_pair(client)
      {:ok, %Client{}}

  """
  def regenerate_client_key_pair(%Client{} = client, public_key \\ nil, private_key \\ nil) do
    params =
      case {public_key, private_key} do
        {public_key, private_key} when is_nil(private_key) or is_nil(public_key) ->
          %{}

        _ ->
          %{public_key: public_key, private_key: private_key}
      end

    with {:ok, client} <-
           client
           |> Client.key_pair_changeset(params)
           |> repo().update(),
         :ok <- Clients.invalidate(%Oauth.Client{id: client.id}) do
      {:ok, client}
    end
  end

  @doc """
  Updates a client.

  ## Examples

      iex> update_client(client, %{field: new_value})
      {:ok, %Client{}}

      iex> update_client(client, %{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def update_client(%Client{} = client, attrs) do
    with {:ok, client} <- client |> Client.update_changeset(attrs) |> repo().update(),
         :ok <- Clients.invalidate(%Oauth.Client{id: client.id}) do
      {:ok, client}
    end
  end

  @doc """
  Deletes a Client.

  ## Examples

      iex> delete_client(client)
      {:ok, %Client{}}

      iex> delete_client(client)
      {:error, %Ecto.Changeset{}}

  """
  def delete_client(%Client{} = client) do
    with :ok <- Clients.invalidate(%Oauth.Client{id: client.id}) do
      repo().delete(client)
    end
  end
end
