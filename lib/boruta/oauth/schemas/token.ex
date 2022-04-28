defmodule Boruta.Oauth.Token do
  @moduledoc """
  OAuth access token and code schema and utilities
  """

  import Boruta.Config, only: [resource_owners: 0]

  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Token

  @enforce_keys [:type]
  defstruct type: nil,
            value: nil,
            state: nil,
            nonce: nil,
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

  # TODO manage nil atribute values and watch for aftereffects of them
  @type t :: %__MODULE__{
          type: String.t(),
          value: String.t() | nil,
          state: String.t() | nil,
          nonce: String.t() | nil,
          scope: String.t(),
          redirect_uri: String.t() | nil,
          expires_at: integer() | nil,
          client: Boruta.Oauth.Client.t() | nil,
          sub: String.t() | nil,
          resource_owner: Boruta.Oauth.ResourceOwner.t() | nil,
          refresh_token: String.t() | nil,
          code_challenge: String.t() | nil,
          code_challenge_hash: String.t() | nil,
          code_challenge_method: String.t() | nil,
          inserted_at: DateTime.t() | nil,
          revoked_at: DateTime.t() | nil
        }

  @doc """
  Determines if a token is expired

  ## Examples
      iex> expired?(%Boruta.Oauth.Token{expires_at: 1628260754})
      false

      iex> expired?(%Boruta.Oauth.Token{expires_at: 0}) # 1st january 1970
      true
  """
  @spec expired?(token :: Token.t()) :: :ok | boolean()
  @spec expired?(
          token :: Token.t(),
          type :: :access_token | :refresh_token
        ) :: boolean()
  @spec expired?(
          token :: Token.t(),
          type :: :access_token | :refresh_token,
          now :: integer()
        ) :: boolean()
  def expired?(token, type \\ :access_token, now \\ :os.system_time(:seconds))

  def expired?(%Token{expires_at: expires_at}, :access_token, now) do
    now >= expires_at
  end

  def expired?(
        %Token{inserted_at: inserted_at, client: %Client{refresh_token_ttl: refresh_token_ttl}},
        :refresh_token,
        now
      ) do
    expires_at = DateTime.add(inserted_at, refresh_token_ttl, :second) |> DateTime.to_unix()

    now >= expires_at
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
  @spec ensure_valid(token :: Token.t(), type :: :access_token | :refresh_token) ::
          :ok | {:error, String.t()}
  def ensure_valid(token, type \\ :access_token) do
    case {revoked?(token), expired?(token, type)} do
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
    :crypto.hash(:sha512, string) |> Base.encode16()
  end

  def userinfo(%Token{resource_owner: %ResourceOwner{} = resource_owner, scope: scope}) do
    userinfo =
      resource_owner
      |> resource_owners().claims(scope)
      |> Map.put(:sub, resource_owner.sub)

    {:ok, userinfo}
  end

  def userinfo(_token) do
    {:error,
     %Error{
       status: :bad_request,
       error: :invalid_access_token,
       error_description:
         "Provided access token is invalid."
     }}
  end
end
