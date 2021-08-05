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
      iex> expired?(%Boruta.Oauth.Token{expires_at: 1924992000}) # 1st january 2031
      false

      iex> expired?(%Boruta.Oauth.Token{expires_at: 0}) # 1st january 1970
      true
  """
  @spec expired?(%Token{expires_at: integer()}) :: :ok | boolean()
  def expired?(%Token{expires_at: expires_at}) do
    :os.system_time(:seconds) >= expires_at
  end

  @doc """
  Determines if a token is revoked.

  ## Examples
      iex> revoked?(%Boruta.Oauth.Token{revoked_at: nil})
      :ok

      iex> revoked?(%Boruta.Oauth.Token{})
      false
  """
  @spec revoked?(token :: Token.t()) :: boolean()
  def revoked?(%Token{revoked_at: nil}), do: false
  def revoked?(%Token{revoked_at: _}), do: true

  @doc """
  Determines if a token is valid, neither expired nor revoked.

  ## Examples
      iex> ensure_valid(%Boruta.Oauth.Token{revoked_at: nil})
      :ok

      iex> ensure_valid(%Boruta.Oauth.Token{})
      {:error, "Token revoked."}
  """
  @spec ensure_valid(token :: Token.t()) :: :ok | {:error, String.t()}
  def ensure_valid(token) do
    case {revoked?(token), expired?(token)} do
      {true, _} -> {:error, "Token revoked."}
      {_, true} -> {:error, "Token expired."}
      _ -> :ok
    end
  end

  @doc """
  Returns an hexadecimal SHA512 hash of given string

  ## Examples
      iex> hash("foo")
      "F7FBBA6E0636F890E56FBBF3283E524C6FA3204AE298382D624741D0DC6638326E282C41BE5E4254D8820772C5518A2C5A8C0C7F7EDA19594A7EB539453E1ED7"
  """
  @spec hash(string :: String.t()) :: hashed_string :: String.t()
  def hash(string) do
    :crypto.hash(:sha512, string) |> Base.encode16
  end
end
