defmodule Boruta.Ecto.Client do
  @moduledoc """
  Ecto Adapter Client Schema
  """

  use Ecto.Schema

  import Ecto.Changeset

  import Boruta.Config,
    only: [
      token_generator: 0,
      repo: 0,
      access_token_max_ttl: 0,
      authorization_code_max_ttl: 0,
      authorization_request_max_ttl: 0,
      id_token_max_ttl: 0,
      refresh_token_max_ttl: 0
    ]

  alias Boruta.Did
  alias Boruta.Ecto.Scope
  alias Boruta.Oauth
  alias Boruta.Oauth.Client
  alias Boruta.Universal
  alias ExJsonSchema.Validator.Error.BorutaFormatter

  @type t :: %__MODULE__{
          secret: String.t(),
          authorize_scope: boolean(),
          redirect_uris: list(String.t()),
          supported_grant_types: list(String.t()),
          enforce_dpop: boolean(),
          enforce_tx_code: boolean(),
          pkce: boolean(),
          public_refresh_token: boolean(),
          public_revoke: boolean(),
          access_token_ttl: integer(),
          authorization_code_ttl: integer(),
          refresh_token_ttl: integer(),
          authorized_scopes: Ecto.Association.NotLoaded.t() | list(Scope.t()),
          id_token_ttl: integer(),
          id_token_signature_alg: String.t(),
          token_endpoint_auth_methods: list(String.t()),
          token_endpoint_jwt_auth_alg: String.t(),
          userinfo_signed_response_alg: String.t() | nil,
          jwt_public_key: String.t(),
          public_key: String.t(),
          private_key: String.t(),
          response_mode: String.t(),
          signatures_adapter: String.t()
        }

  @token_endpoint_auth_methods [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt"
  ]

  @token_endpoint_jwt_auth_algs [
    :RS256,
    :RS384,
    :RS512,
    :HS256,
    :HS384,
    :HS512
  ]

  @response_modes ["post", "direct_post"]

  @key_pair_type_schema %{
    "type" => "object",
    "properties" => %{
      "type" => %{"type" => "string", "pattern" => "^ec|rsa|universal$"},
      "modulus_size" => %{"type" => "string"},
      "exponent_size" => %{"type" => "string"},
      "curve" => %{"type" => "string", "pattern" => "^P-256|P-384|P-512$"}
    },
    "required" => ["type"]
  }

  @key_pair_type_jwt_algs %{
    "ec" => [
      "ES256",
      "ES384",
      "ES512",
      "HS256",
      "HS384",
      "HS512"
    ],
    "rsa" => [
      "RS256",
      "RS384",
      "RS512",
      "HS256",
      "HS384",
      "HS512"
    ],
    "universal" => [
      "EdDSA"
    ]
  }

  @primary_key {:id, Ecto.UUID, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts type: :utc_datetime
  schema "oauth_clients" do
    field(:public_client_id, :string)
    field(:name, :string)
    field(:secret, :string)
    field(:confidential, :boolean, default: false)
    field(:authorize_scope, :boolean, default: false)
    field(:enforce_tx_code, :boolean, default: false)
    field(:enforce_dpop, :boolean, default: false)
    field(:redirect_uris, {:array, :string}, default: [])

    field(:supported_grant_types, {:array, :string}, default: Oauth.Client.grant_types())

    field(:pkce, :boolean, default: false)
    field(:public_refresh_token, :boolean, default: false)
    field(:public_revoke, :boolean, default: false)

    field(:access_token_ttl, :integer)
    field(:authorization_code_ttl, :integer)
    field(:authorization_request_ttl, :integer)
    field(:id_token_ttl, :integer)
    field(:refresh_token_ttl, :integer)

    field(:id_token_signature_alg, :string, default: "RS512")
    field(:id_token_kid, :string)

    field(:signatures_adapter, :string, default: "Elixir.Boruta.Internal.Signatures")

    field(:key_pair_type, :map,
      default: %{
        "type" => "rsa",
        "modulus_size" => "1024",
        "exponent_size" => "65537"
      }
    )

    field(:public_key, :string)
    field(:private_key, :string)
    field(:did, :string)

    field(:token_endpoint_auth_methods, {:array, :string},
      default: ["client_secret_basic", "client_secret_post"]
    )

    field(:token_endpoint_jwt_auth_alg, :string, default: "HS256")
    field(:jwt_public_key, :string)
    field(:jwk, :map, virtual: true)
    field(:jwks_uri, :string)

    field(:userinfo_signed_response_alg, :string)

    field(:logo_uri, :string)
    field(:metadata, :map, default: %{})

    field(:response_mode, :string, default: "direct_post")

    many_to_many :authorized_scopes, Scope,
      join_through: "oauth_clients_scopes",
      on_replace: :delete

    timestamps()
  end

  def create_changeset(client, attrs) do
    client
    |> repo().preload(:authorized_scopes)
    |> cast(attrs, [
      :id,
      :name,
      :secret,
      :confidential,
      :access_token_ttl,
      :authorization_code_ttl,
      :authorization_request_ttl,
      :refresh_token_ttl,
      :id_token_ttl,
      :redirect_uris,
      :authorize_scope,
      :enforce_dpop,
      :enforce_tx_code,
      :supported_grant_types,
      :token_endpoint_auth_methods,
      :token_endpoint_jwt_auth_alg,
      :jwk,
      :jwks_uri,
      :jwt_public_key,
      :pkce,
      :public_refresh_token,
      :public_revoke,
      :id_token_signature_alg,
      :id_token_kid,
      :userinfo_signed_response_alg,
      :logo_uri,
      :metadata,
      :response_mode,
      :signatures_adapter,
      :key_pair_type,
    ])
    |> validate_required([:redirect_uris, :key_pair_type])
    |> unique_constraint(:id, name: :clients_pkey)
    |> change_access_token_ttl()
    |> change_authorization_code_ttl()
    |> change_authorization_request_ttl()
    |> change_id_token_ttl()
    |> change_refresh_token_ttl()
    |> validate_redirect_uris()
    |> validate_supported_grant_types()
    |> validate_id_token_signature_alg()
    |> validate_inclusion(:response_mode, @response_modes)
    |> validate_subset(:token_endpoint_auth_methods, @token_endpoint_auth_methods)
    |> validate_inclusion(
      :token_endpoint_jwt_auth_alg,
      Enum.map(@token_endpoint_jwt_auth_algs, &Atom.to_string/1)
    )
    |> validate_inclusion(
      :userinfo_signed_response_alg,
      Enum.map(Client.Crypto.signature_algorithms(), &Atom.to_string/1)
    )
    |> put_assoc(:authorized_scopes, parse_authorized_scopes(attrs))
    |> translate_jwk()
    |> validate_signatures_adapter()
    |> validate_key_pair_type()
    |> generate_key_pair()
    |> put_secret()
    |> validate_required(:secret)
  end

  def update_changeset(client, attrs) do
    client
    |> repo().preload(:authorized_scopes)
    |> cast(attrs, [
      :name,
      :secret,
      :confidential,
      :access_token_ttl,
      :authorization_code_ttl,
      :authorization_request_ttl,
      :refresh_token_ttl,
      :id_token_ttl,
      :redirect_uris,
      :authorize_scope,
      :enforce_dpop,
      :enforce_tx_code,
      :supported_grant_types,
      :token_endpoint_auth_methods,
      :token_endpoint_jwt_auth_alg,
      :jwk,
      :jwks_uri,
      :jwt_public_key,
      :pkce,
      :public_refresh_token,
      :public_revoke,
      :id_token_signature_alg,
      :id_token_kid,
      :userinfo_signed_response_alg,
      :logo_uri,
      :metadata,
      :response_mode,
      :signatures_adapter,
      :key_pair_type
    ])
    |> validate_required([
      :authorization_code_ttl,
      :access_token_ttl,
      :refresh_token_ttl,
      :id_token_ttl,
      :key_pair_type
    ])
    |> validate_inclusion(:access_token_ttl, 1..access_token_max_ttl())
    |> validate_inclusion(:authorization_code_ttl, 1..authorization_code_max_ttl())
    |> validate_inclusion(:access_token_ttl, 1..authorization_request_max_ttl())
    |> validate_inclusion(:refresh_token_ttl, 1..refresh_token_max_ttl())
    |> validate_inclusion(:refresh_token_ttl, 1..id_token_max_ttl())
    |> validate_inclusion(:response_mode, @response_modes)
    |> validate_subset(:token_endpoint_auth_methods, @token_endpoint_auth_methods)
    |> validate_inclusion(
      :token_endpoint_jwt_auth_alg,
      Enum.map(@token_endpoint_jwt_auth_algs, &Atom.to_string/1)
    )
    |> validate_inclusion(
      :userinfo_signed_response_alg,
      Enum.map(Client.Crypto.signature_algorithms(), &Atom.to_string/1)
    )
    |> validate_redirect_uris()
    |> validate_supported_grant_types()
    |> validate_id_token_signature_alg()
    |> put_assoc(:authorized_scopes, parse_authorized_scopes(attrs))
    |> validate_signatures_adapter()
    |> validate_key_pair_type()
    |> translate_jwk()
  end

  def secret_changeset(client, secret \\ nil) do
    client
    |> cast(%{secret: secret}, [:secret])
    |> put_secret()
    |> validate_required(:secret)
  end

  def did_changeset(client) do
    change(client)
    |> put_did()
  end

  def key_pair_changeset(client, attrs \\ %{}) do
    client
    |> cast(attrs, [:public_key, :private_key])
    |> generate_key_pair()
  end

  defp change_access_token_ttl(changeset) do
    case fetch_change(changeset, :access_token_ttl) do
      {:ok, _access_token_ttl} ->
        validate_inclusion(changeset, :access_token_ttl, 1..access_token_max_ttl())

      :error ->
        put_change(changeset, :access_token_ttl, access_token_max_ttl())
    end
  end

  defp change_authorization_code_ttl(changeset) do
    case fetch_change(changeset, :authorization_code_ttl) do
      {:ok, _authorization_code_ttl} ->
        validate_inclusion(changeset, :authorization_code_ttl, 1..authorization_code_max_ttl())

      :error ->
        put_change(changeset, :authorization_code_ttl, authorization_code_max_ttl())
    end
  end

  defp change_authorization_request_ttl(changeset) do
    case fetch_change(changeset, :authorization_request_ttl) do
      {:ok, _authorization_request_ttl} ->
        validate_inclusion(
          changeset,
          :authorization_request_ttl,
          1..authorization_request_max_ttl()
        )

      :error ->
        put_change(changeset, :authorization_request_ttl, authorization_request_max_ttl())
    end
  end

  defp change_refresh_token_ttl(changeset) do
    case fetch_change(changeset, :refresh_token_ttl) do
      {:ok, _access_token_ttl} ->
        validate_inclusion(changeset, :refresh_token_ttl, 1..refresh_token_max_ttl())

      :error ->
        put_change(changeset, :refresh_token_ttl, refresh_token_max_ttl())
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

  defp validate_signatures_adapter(changeset) do
    key_pair_type = get_field(changeset, :key_pair_type)

    case key_pair_type do
      %{"type" => "universal"} ->
        validate_inclusion(changeset, :signatures_adapter, [Atom.to_string(Boruta.Universal.Signatures)])
      %{"type" => type} when type in ["ec", "rsa"] ->
        validate_inclusion(changeset, :signatures_adapter, [Atom.to_string(Boruta.Internal.Signatures)])
      _ ->
        add_error(changeset, :signatures_adapter, "unknown key pair type")
    end
  end

  defp validate_key_pair_type(changeset) do
    key_pair_type = get_field(changeset, :key_pair_type)

    case ExJsonSchema.Validator.validate(
           @key_pair_type_schema,
           key_pair_type,
           error_formatter: BorutaFormatter
         ) do
      :ok ->
        changeset
        |> validate_inclusion(
          :id_token_signature_alg,
          @key_pair_type_jwt_algs[key_pair_type["type"]]
        )
        |> validate_inclusion(
          :userinfo_signed_response_alg,
          @key_pair_type_jwt_algs[key_pair_type["type"]]
        )

      {:error, errors} ->
        add_error(changeset, :key_pair_type, "validation failed: #{Enum.join(errors, " ")}")
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
    server_grant_types = Oauth.Client.grant_types()

    validate_change(changeset, :supported_grant_types, fn :supported_grant_types,
                                                          current_grant_types ->
      case Enum.empty?(current_grant_types -- server_grant_types) do
        true -> []
        false -> [supported_grant_types: "must be part of #{Enum.join(server_grant_types, ", ")}"]
      end
    end)
  end

  defp validate_uri(nil), do: "empty values are not allowed"

  defp validate_uri("" <> uri) do
    case URI.parse(uri) do
      %URI{scheme: scheme, host: host, fragment: fragment}
      when not is_nil(scheme) and not is_nil(host) and is_nil(fragment) ->
        nil

      _ ->
        "`#{uri}` is invalid"
    end
  end

  defp validate_id_token_signature_alg(changeset) do
    signature_algorithms = Enum.map(Client.Crypto.signature_algorithms(), &Atom.to_string/1)
    validate_inclusion(changeset, :id_token_signature_alg, signature_algorithms)
  end

  defp parse_authorized_scopes(attrs) do
    Enum.map(
      attrs["authorized_scopes"] || attrs[:authorized_scopes] || [],
      fn scope_attrs ->
        case apply_action(Scope.assoc_changeset(%Scope{}, scope_attrs), :replace) do
          {:ok, %Scope{id: id}} when is_binary(id) ->
            repo().get_by(Scope, id: id)

          {:ok, %Scope{name: name}} when is_binary(name) ->
            repo().get_by(Scope, name: name) || %Scope{name: name}

          _ ->
            nil
        end
      end
    )
    |> Enum.reject(&is_nil/1)
  end

  defp translate_jwk(%Ecto.Changeset{changes: %{jwk: jwk}} = changeset) do
    {_key_type, pem} = JOSE.JWK.from_map(jwk) |> JOSE.JWK.to_pem()

    put_change(changeset, :jwt_public_key, pem)
  end

  defp translate_jwk(changeset), do: changeset

  defp generate_key_pair(%Ecto.Changeset{changes: %{private_key: _private_key}} = changeset) do
    changeset
  end

  defp generate_key_pair(changeset) do
    private_key =
      case get_field(changeset, :key_pair_type) do
        %{"type" => "rsa", "modulus_size" => modulus_size, "exponent_size" => exponent_size} ->
          JOSE.JWK.generate_key(
            {:rsa, String.to_integer(modulus_size), String.to_integer(exponent_size)}
          )

        %{"type" => "ec", "curve" => curve} ->
          JOSE.JWK.generate_key({:ec, curve})

        %{"type" => "universal"} ->
          "universal"

        _ ->
          nil
      end

    case private_key do
      nil ->
        add_error(changeset, :private_key, "private_key_type is invalid")

      "universal" ->
        with {:ok, did, jwk} <- Did.create("key"),
             {:ok, key_id} <- Universal.Signatures.SigningKey.get_key_by_did(did) do
          "did:key:" <> key = did
          public_key = JOSE.JWK.from_map(jwk)
          {_type, public_pem} = JOSE.JWK.to_pem(public_key)

          changeset
          |> put_change(:private_key, key_id["id"])
          |> put_change(:public_key, public_pem)
          |> put_change(:did, "#{did}##{key}")
          |> put_change(:signatures_adapter, Boruta.Universal.Signatures |> Atom.to_string())
          |> put_change(:id_token_signature_alg, "EdDSA")
          |> put_change(:userinfo_signed_response_alg, "EdDSA")
        else
          {:error, error} ->
            add_error(changeset, :private_key, error)
        end

      private_key ->
        public_key = JOSE.JWK.to_public(private_key)

        {_type, public_pem} = JOSE.JWK.to_pem(public_key)
        {_type, private_pem} = JOSE.JWK.to_pem(private_key)

        changeset
        |> put_change(:public_key, public_pem)
        |> put_change(:private_key, private_pem)
        |> put_change(:signatures_adapter, Boruta.Internal.Signatures |> Atom.to_string())
    end
  end

  defp put_secret(%Ecto.Changeset{data: data, changes: changes} = changeset) do
    case fetch_change(changeset, :secret) do
      {:ok, nil} ->
        put_change(changeset, :secret, token_generator().secret(struct(data, changes)))

      {:ok, _secret} ->
        changeset

      :error ->
        put_change(changeset, :secret, token_generator().secret(struct(data, changes)))
    end
  end

  defp put_did(%Ecto.Changeset{} = changeset) do
    case get_field(changeset, :public_key) do
      nil ->
        changeset

      pem ->
        {_, jwk} = JOSE.JWK.from_pem(pem) |> JOSE.JWK.to_map()

        case Did.create("key", jwk) do
          {:ok, did, _jwk} ->
            "did:key:" <> key = did
            put_change(changeset, :did, "#{did}##{key}")

          {:error, error} ->
            add_error(changeset, :did, error)
        end
    end
  end
end
