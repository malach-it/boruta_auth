defmodule Boruta.Oauth.Token do
  @moduledoc """
  Token schema. Representing both access tokens and codes.
  """

  alias Boruta.Oauth.Token

  defstruct [
    id: nil,
    type: nil,
    value: nil,
    state: nil,
    scope: nil,
    redirect_uri: nil,
    expires_at: nil,
    client: nil,
    sub: nil,
    resource_owner: nil,
    refresh_token: nil,
    inserted_at: nil,
    revoked_at: nil,
    code_challenge: nil,
    code_challenge_hash: nil,
    code_challenge_method: nil
  ]

  @type t :: %__MODULE__{
    type:  String.t(),
    value: String.t(),
    state: String.t(),
    scope: String.t(),
    redirect_uri: String.t(),
    expires_at: integer(),
    client: Boruta.Oauth.Client.t(),
    sub: String.t(),
    resource_owner: Boruta.Oauth.ResourceOwner.t() | nil,
    refresh_token: String.t(),
    code_challenge: String.t(),
    code_challenge_hash: String.t(),
    code_challenge_method: String.t(),
    inserted_at: DateTime.t(),
    revoked_at: DateTime.t()
  }
  @doc """
  Determines if a token is expired

  ## Examples
      iex> expired?(%Boruta.Oauth.Token{expires_at: 1638316800}) # 1st january 2021
      :ok

      iex> expired?(%Boruta.Oauth.Token{expires_at: 0}) # 1st january 1970
      {:error, "Token expired."}
  """
  # TODO move this out of the schema
  @spec expired?(%Token{expires_at: integer()}) :: :ok | {:error, String.t()}
  def expired?(%Token{expires_at: expires_at}) do
    case :os.system_time(:seconds) <= expires_at do
      true -> :ok
      false -> {:error, "Token expired."}
    end
  end

  @spec revoked?(token :: Token.t()) :: :ok | {:error, String.t()}
  def revoked?(%Token{revoked_at: nil}), do: :ok
  def revoked?(%Token{revoked_at: _}), do: {:error, "Token revoked."}

  @spec hash(string :: String.t()) :: hashed_string :: String.t()
  def hash(string) do
    :crypto.hash(:sha512, string) |> Base.encode16
  end
end
