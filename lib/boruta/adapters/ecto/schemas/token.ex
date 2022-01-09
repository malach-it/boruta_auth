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
          state: String.t(),
          nonce: String.t(),
          scope: String.t(),
          redirect_uri: String.t(),
          expires_at: integer(),
          client: Client.t(),
          sub: String.t(),
          revoked_at: DateTime.t()
        }

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts type: :utc_datetime_usec
  schema "oauth_tokens" do
    field(:type, :string)
    field(:value, :string)
    field(:refresh_token, :string)
    field(:previous_token, :string)
    field(:state, :string)
    field(:nonce, :string)
    field(:scope, :string, default: "")
    field(:redirect_uri, :string)
    field(:expires_at, :integer)
    field(:revoked_at, :utc_datetime_usec)
    field(:code_challenge, :string, virtual: true)
    field(:code_challenge_hash, :string)
    field(:code_challenge_method, :string, default: "plain")
    field(:access_token_ttl, :integer, virtual: true)
    field(:authorization_code_ttl, :integer, virtual: true)

    belongs_to(:client, Client)
    field(:sub, :string)

    timestamps()
  end

  def changeset(token, attrs) do
    token
    |> cast(attrs, [:client_id, :redirect_uri, :sub, :state, :nonce, :scope, :access_token_ttl])
    |> validate_required([:access_token_ttl])
    |> validate_required([:client_id])
    |> foreign_key_constraint(:client_id)
    |> put_change(:type, "access_token")
    |> put_value()
    |> put_expires_at()
  end

  def changeset_with_refresh_token(token, attrs) do
    token
    |> cast(attrs, [:access_token_ttl, :client_id, :redirect_uri, :sub, :state, :nonce, :scope, :previous_token])
    |> validate_required([:access_token_ttl, :client_id])
    |> foreign_key_constraint(:client_id)
    |> put_change(:type, "access_token")
    |> put_value()
    |> put_refresh_token()
    |> put_expires_at()
  end

  def code_changeset(token, attrs) do
    token
    |> cast(attrs, [
      :authorization_code_ttl,
      :client_id,
      :sub,
      :redirect_uri,
      :state,
      :nonce,
      :scope
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
      :authorization_code_ttl,
      :client_id,
      :sub,
      :redirect_uri,
      :state,
      :nonce,
      :scope,
      :code_challenge,
      :code_challenge_method
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
    |> put_code_expires_at()
    |> put_code_challenge_method()
    |> encrypt_code_challenge()
  end

  @doc false
  def revoke_changeset(token) do
    now = DateTime.utc_now()

    change(token, revoked_at: now)
  end

  defp put_value(%Ecto.Changeset{data: data, changes: changes} = changeset) do
    put_change(
      changeset,
      :value,
      token_generator().generate(:access_token, struct(data, changes))
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
    code_challenge_method = case get_field(changeset, :code_challenge_method) do
      nil -> "plain"
      code_challenge_method -> code_challenge_method
    end

    put_change(changeset, :code_challenge_method, code_challenge_method)
  end

  defp encrypt_code_challenge(%Ecto.Changeset{valid?: true} = changeset) do
    changeset
    |> put_change(
      :code_challenge_hash,
      changeset |> get_field(:code_challenge, "") |> Oauth.Token.hash()
    )
  end
  defp encrypt_code_challenge(changeset), do: changeset
end
