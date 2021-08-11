defmodule Boruta.Ecto.Client do
  @moduledoc """
  Ecto Adapter Client Schema
  """

  use Ecto.Schema

  import Ecto.Changeset
  import Ecto.Query, only: [from: 2]

  import Boruta.Config,
    only: [
      token_generator: 0,
      repo: 0,
      access_token_max_ttl: 0,
      authorization_code_max_ttl: 0,
      id_token_max_ttl: 0
    ]

  alias Boruta.Ecto.Scope

  @type t :: %__MODULE__{
          secret: String.t(),
          authorize_scope: boolean(),
          redirect_uris: list(String.t()),
          supported_grant_types: list(String.t()),
          pkce: boolean(),
          access_token_ttl: integer(),
          authorization_code_ttl: integer(),
          authorized_scopes: Ecto.Association.NotLoaded.t() | list(Scope.t()),
          id_token_ttl: integer(),
          public_key: list(String.t()),
          private_key: list(String.t())
        }

  @grant_types [
    "client_credentials",
    "password",
    "authorization_code",
    "refresh_token",
    "implicit"
  ]

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts type: :utc_datetime
  schema "clients" do
    field(:name, :string)
    field(:secret, :string)
    field(:authorize_scope, :boolean, default: false)
    field(:redirect_uris, {:array, :string}, default: [])

    field(:supported_grant_types, {:array, :string},
      default: [
        "client_credentials",
        "password",
        "authorization_code",
        "refresh_token",
        "implicit"
      ]
    )

    field(:pkce, :boolean, default: false)

    field(:access_token_ttl, :integer)
    field(:authorization_code_ttl, :integer)
    field(:id_token_ttl, :integer)

    field(:public_key, :string)
    field(:private_key, :string)

    many_to_many :authorized_scopes, Scope, join_through: "clients_scopes", on_replace: :delete

    timestamps()
  end

  def create_changeset(client, attrs) do
    client
    |> repo().preload(:authorized_scopes)
    |> cast(attrs, [
      :name,
      :access_token_ttl,
      :authorization_code_ttl,
      :id_token_ttl,
      :redirect_uris,
      :authorize_scope,
      :supported_grant_types,
      :pkce
    ])
    |> change_access_token_ttl()
    |> change_authorization_code_ttl()
    |> change_id_token_ttl()
    |> validate_redirect_uris
    |> validate_supported_grant_types()
    |> put_assoc(:authorized_scopes, parse_authorized_scopes(attrs))
    |> generate_key_pair()
    |> put_secret()
  end

  def update_changeset(client, attrs) do
    client
    |> repo().preload(:authorized_scopes)
    |> cast(attrs, [
      :name,
      :access_token_ttl,
      :authorization_code_ttl,
      :redirect_uris,
      :authorize_scope,
      :supported_grant_types,
      :pkce
    ])
    |> validate_required([:authorization_code_ttl, :access_token_ttl])
    |> validate_inclusion(:access_token_ttl, 1..access_token_max_ttl())
    |> validate_inclusion(:authorization_code_ttl, 1..authorization_code_max_ttl())
    |> validate_redirect_uris()
    |> validate_supported_grant_types()
    |> put_assoc(:authorized_scopes, parse_authorized_scopes(attrs))
  end

  defp change_authorization_code_ttl(changeset) do
    case fetch_change(changeset, :authorization_code_ttl) do
      {:ok, _authorization_code_ttl} ->
        validate_inclusion(changeset, :authorization_code_ttl, 1..authorization_code_max_ttl())
      :error ->
        put_change(changeset, :authorization_code_ttl, authorization_code_max_ttl())
    end
  end

  defp change_access_token_ttl(changeset) do
    case fetch_change(changeset, :access_token_ttl) do
      {:ok, _access_token_ttl} ->
        validate_inclusion(changeset, :access_token_ttl, 1..access_token_max_ttl())
      :error ->
        put_change(changeset, :access_token_ttl, access_token_max_ttl())
    end
  end

  defp change_id_token_ttl(changeset) do
    case fetch_change(changeset, :id_token_ttl) do
      {:ok, _id_token_ttl} ->
        validate_inclusion(changeset, :id_token_ttl, 1..id_token_max_ttl())
      :error ->
        put_change(changeset, :id_token_ttl, id_token_max_ttl())
    end
  end

  defp validate_redirect_uris(changeset) do
    validate_change(changeset, :redirect_uris, fn field, values ->
      Enum.map(values, &validate_uri/1)
      |> Enum.reject(&is_nil/1)
      |> Enum.map(fn error -> {field, error} end)
    end)
  end

  defp validate_supported_grant_types(changeset) do
    validate_change(changeset, :supported_grant_types, fn :supported_grant_types, grant_types ->
      case Enum.empty?(grant_types -- @grant_types) do
        true -> []
        false -> [supported_grant_types: "must be one of #{Enum.join(@grant_types, ", ")}"]
      end
    end)
  end

  defp validate_uri(nil), do: "empty values are not allowed"

  defp validate_uri("" <> uri) do
    case URI.parse(uri) do
      %URI{scheme: scheme, host: host}
      when not is_nil(scheme) and not is_nil(host) ->
        nil

      _ ->
        "`#{uri}` is invalid"
    end
  end

  defp parse_authorized_scopes(attrs) do
    authorized_scope_ids =
      Enum.map(
        attrs["authorized_scopes"] || attrs[:authorized_scopes] || [],
        fn scope_attrs ->
          case apply_action(Scope.assoc_changeset(%Scope{}, scope_attrs), :replace) do
            {:ok, %{id: id}} -> id
            _ -> nil
          end
        end
      )

    authorized_scope_ids =
      authorized_scope_ids
      |> Enum.reject(&is_nil/1)

    repo().all(
      from s in Scope,
        where: s.id in ^authorized_scope_ids
    )
  end

  defp generate_key_pair(changeset) do
    private_key = JOSE.JWK.generate_key({:rsa, 1024, 65_537})
    public_key = JOSE.JWK.to_public(private_key)

    {_type, public_pem} = JOSE.JWK.to_pem(public_key)
    {_type, private_pem} = JOSE.JWK.to_pem(private_key)

    changeset
    |> put_change(:public_key, public_pem)
    |> put_change(:private_key, private_pem)
  end

  defp put_secret(%Ecto.Changeset{data: data, changes: changes} = changeset) do
    put_change(changeset, :secret, token_generator().secret(struct(data, changes)))
  end
end
