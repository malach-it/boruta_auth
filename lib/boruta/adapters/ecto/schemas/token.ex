defmodule Boruta.Ecto.Token do
  @moduledoc """
  Ecto Adapter Token Schema
  """

  use Ecto.Schema

  import Ecto.Changeset

  import Boruta.Config,
    only: [
      token_generator: 0
    ]

  alias Boruta.Ecto.Client
  alias Boruta.Oauth

  @type t :: %__MODULE__{
          type: String.t(),
          value: String.t(),
          response_type: String.t() | nil,
          tx_code: String.t() | nil,
          authorization_details: list(),
          state: String.t(),
          nonce: String.t(),
          c_nonce: String.t(),
          scope: String.t(),
          redirect_uri: String.t(),
          expires_at: integer(),
          client: Client.t(),
          public_client_id: String.t(),
          sub: String.t(),
          revoked_at: DateTime.t(),
          refresh_token_revoked_at: DateTime.t(),
          previous_token: String.t() | nil,
          previous_code: String.t() | nil,
          agent_token: String.t() | nil,
          bind_data: map() | nil,
          bind_configuration: map() | nil,
          client_encryption_key: String.t() | nil,
          client_encryption_alg: String.t() | nil
        }

  @authorization_details_schema %{
    "type" => "array",
    "items" => %{
      "type" => "object",
      "properties" => %{
        "type" => %{"type" => "string", "pattern" => "^openid_credential$"},
        "format" => %{"type" => "string"},
        "credential_configuration_id" => %{"type" => "string"},
        "credential_identifiers" => %{"type" => "array", "items" => %{"type" => "string"}}
      },
      "required" => ["type", "format"]
    }
  }

  @c_nonce_length 4

  @primary_key {:id, Ecto.UUID, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts type: :utc_datetime_usec
  schema "oauth_tokens" do
    field(:type, :string)
    field(:value, :string)
    field(:response_type, :string)
    field(:authorization_details, {:array, :map}, default: [])
    field(:presentation_definition, :map)
    field(:refresh_token, :string)
    field(:previous_token, :string)
    field(:previous_code, :string)
    field(:state, :string)
    field(:nonce, :string)
    field(:c_nonce, :string)
    field(:scope, :string, default: "")
    field(:redirect_uri, :string)
    field(:expires_at, :integer)
    field(:revoked_at, :utc_datetime_usec)
    field(:refresh_token_revoked_at, :utc_datetime_usec)
    field(:tx_code, :string)
    field(:code_challenge, :string, virtual: true)
    field(:code_challenge_hash, :string)
    field(:code_challenge_method, :string, default: "plain")
    # TODO rename to token_ttl
    field(:access_token_ttl, :integer, virtual: true)
    field(:authorization_code_ttl, :integer, virtual: true)
    field(:agent_token, :string)
    field(:bind_data, :map)
    field(:bind_configuration, :map)
    field(:client_encryption_key, :map)
    field(:client_encryption_alg, :string)

    field(:resource_owner, :map, virtual: true)

    field(:public_client_id, :string)
    belongs_to(:client, Client)
    field(:sub, :string)

    timestamps()
  end

  @doc false
  def changeset(token, attrs) do
    token
    |> cast(attrs, [
      :client_id,
      :redirect_uri,
      :sub,
      :state,
      :nonce,
      :scope,
      :access_token_ttl,
      :previous_code,
      :authorization_details,
      :agent_token
    ])
    |> validate_required([:access_token_ttl])
    |> validate_required([:client_id])
    |> foreign_key_constraint(:client_id)
    |> put_change(:type, "access_token")
    |> validate_authorization_details()
    |> put_value()
    |> put_c_nonce()
    |> put_expires_at()
  end

  @doc false
  def changeset_with_refresh_token(token, attrs) do
    token
    |> cast(attrs, [
      :access_token_ttl,
      :client_id,
      :redirect_uri,
      :sub,
      :state,
      :nonce,
      :scope,
      :previous_token,
      :previous_code,
      :authorization_details,
      :agent_token
    ])
    |> validate_required([:access_token_ttl, :client_id])
    |> foreign_key_constraint(:client_id)
    |> put_change(:type, "access_token")
    |> put_value()
    |> put_c_nonce()
    |> put_refresh_token()
    |> put_expires_at()
  end

  @doc false
  def data_changeset(token, attrs) do
    token
    |> cast(attrs, [
      :client_id,
      :redirect_uri,
      :sub,
      :state,
      :nonce,
      :scope,
      :access_token_ttl,
      :previous_code,
      :authorization_details,
      :bind_data,
      :bind_configuration
    ])
    |> validate_required([:access_token_ttl, :client_id, :bind_data, :bind_configuration])
    |> foreign_key_constraint(:client_id)
    |> put_change(:type, "agent_token")
    |> validate_authorization_details()
    |> put_value()
    |> put_c_nonce()
    |> put_expires_at()
  end

  @doc false
  def data_changeset_with_refresh_token(token, attrs) do
    token
    |> cast(attrs, [
      :access_token_ttl,
      :client_id,
      :redirect_uri,
      :sub,
      :state,
      :nonce,
      :scope,
      :previous_token,
      :previous_code,
      :authorization_details,
      :bind_data,
      :bind_configuration
    ])
    |> validate_required([:access_token_ttl, :client_id, :bind_data, :bind_configuration])
    |> foreign_key_constraint(:client_id)
    |> put_change(:type, "agent_token")
    |> put_value()
    |> put_c_nonce()
    |> put_refresh_token()
    |> put_expires_at()
  end

  @doc false
  def preauthorized_code_changeset(token, attrs) do
    token
    |> cast(attrs, [
      :response_type,
      :agent_token,
      :authorization_code_ttl,
      :authorization_details,
      :client_id,
      :nonce,
      :presentation_definition,
      :previous_code,
      :public_client_id,
      :redirect_uri,
      :scope,
      :state,
      :sub
    ])
    |> validate_required([:authorization_code_ttl, :client_id])
    |> foreign_key_constraint(:client_id)
    |> put_change(:type, "preauthorized_code")
    |> put_value()
    |> put_tx_code()
    |> put_code_expires_at()
  end

  @doc false
  def pkce_preauthorized_code_changeset(token, attrs) do
    token
    |> cast(attrs, [
      :response_type,
      :agent_token,
      :authorization_code_ttl,
      :authorization_details,
      :client_id,
      :code_challenge,
      :code_challenge_method,
      :nonce,
      :presentation_definition,
      :previous_code,
      :public_client_id,
      :redirect_uri,
      :scope,
      :state,
      :sub
    ])
    |> validate_required([
      :authorization_code_ttl,
      :client_id,
      :code_challenge
    ])
    |> foreign_key_constraint(:client_id)
    |> put_change(:type, "preauthorized_code")
    |> put_value()
    |> put_tx_code()
    |> put_code_expires_at()
    |> put_code_challenge_method()
    |> encrypt_code_challenge()
  end

  @doc false
  def code_changeset(token, attrs) do
    token
    |> cast(attrs, [
      :response_type,
      :authorization_code_ttl,
      :client_id,
      :public_client_id,
      :sub,
      :redirect_uri,
      :state,
      :nonce,
      :scope,
      :authorization_details,
      :presentation_definition,
      :client_encryption_key,
      :client_encryption_alg,
      :previous_code
    ])
    |> validate_required([:authorization_code_ttl, :client_id, :sub, :redirect_uri])
    |> foreign_key_constraint(:client_id)
    |> put_change(:type, "code")
    |> put_value()
    |> put_code_expires_at()
  end

  @doc false
  def pkce_code_changeset(token, attrs) do
    token
    |> cast(attrs, [
      :response_type,
      :authorization_code_ttl,
      :client_id,
      :public_client_id,
      :sub,
      :redirect_uri,
      :state,
      :nonce,
      :scope,
      :code_challenge,
      :code_challenge_method,
      :authorization_details,
      :presentation_definition,
      :client_encryption_key,
      :client_encryption_alg,
      :previous_code
    ])
    |> validate_required([
      :authorization_code_ttl,
      :client_id,
      :sub,
      :redirect_uri,
      :code_challenge
    ])
    |> foreign_key_constraint(:client_id)
    |> put_change(:type, "code")
    |> put_value()
    |> put_c_nonce()
    |> put_code_expires_at()
    |> put_code_challenge_method()
    |> encrypt_code_challenge()
  end

  @doc false
  def sub_changeset(code, sub) do
    change(code, %{sub: sub, type: "code"})
  end

  @doc false
  def revoke_refresh_token_changeset(token) do
    now = DateTime.utc_now()

    change(token, refresh_token_revoked_at: now)
  end

  @doc false
  def revoke_changeset(token) do
    now = DateTime.utc_now()

    change(token, revoked_at: now)
  end

  @doc false
  def client_encryption_changeset(token, attrs) do
    token
    |> cast(attrs, [
      :client_encryption_key,
      :client_encryption_alg
    ])
  end

  defp put_value(%Ecto.Changeset{data: data, changes: changes} = changeset) do
    put_change(
      changeset,
      :value,
      token_generator().generate(:access_token, struct(data, changes))
    )
  end

  defp put_tx_code(%Ecto.Changeset{data: data, changes: changes} = changeset) do
    put_change(changeset, :tx_code, token_generator().generate(:tx_code, struct(data, changes)))
  end

  defp put_c_nonce(changeset) do
    put_change(
      changeset,
      :c_nonce,
      SecureRandom.hex(@c_nonce_length)
    )
  end

  defp put_refresh_token(%Ecto.Changeset{data: data, changes: changes} = changeset) do
    put_change(
      changeset,
      :refresh_token,
      token_generator().generate(:refresh_token, struct(data, changes))
    )
  end

  defp put_expires_at(changeset) do
    {_type, access_token_ttl} = fetch_field(changeset, :access_token_ttl)

    put_change(changeset, :expires_at, :os.system_time(:seconds) + access_token_ttl)
  end

  defp put_code_expires_at(changeset) do
    {_type, authorization_code_ttl} = fetch_field(changeset, :authorization_code_ttl)

    put_change(changeset, :expires_at, :os.system_time(:seconds) + authorization_code_ttl)
  end

  defp put_code_challenge_method(changeset) do
    code_challenge_method =
      case get_field(changeset, :code_challenge_method) do
        nil -> "plain"
        code_challenge_method -> code_challenge_method
      end

    put_change(changeset, :code_challenge_method, code_challenge_method)
  end

  defp encrypt_code_challenge(changeset) do
    case get_field(changeset, :code_challenge) do
      code_challenge when not is_nil(code_challenge) and code_challenge != "" ->
        changeset
        |> put_change(
          :code_challenge_hash,
          Oauth.Token.hash(code_challenge)
        )

      _ ->
        changeset
    end
  end

  defp validate_authorization_details(changeset) do
    with [_h | _t] = authorization_details <- get_field(changeset, :authorization_details),
         :ok <-
           ExJsonSchema.Validator.validate(
             @authorization_details_schema,
             authorization_details,
             error_formatter: BorutaFormatter
           ) do
      changeset
    else
      {:error, errors} when is_list(errors) ->
        error = "authorization_details validation failed. " <> Enum.join(errors, " ")
        add_error(changeset, :authorization_details, error)

      {:error, error} ->
        error = "authorization_details validation failed. #{inspect(error)}"
        add_error(changeset, :authorization_details, error)

      _ ->
        changeset
    end
  end
end
