defmodule Boruta.Oauth.TokenResponse do
  @moduledoc """
  Response returned in case of access token request success. Provides utilities and mandatory data needed to respond to the token part of client credentials, resource owner password, code and hybrid flows.
  """

  alias Boruta.CodesAdapter
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Token
  alias Boruta.Oauth.TokenResponse

  @enforce_keys [:expires_in]
  defstruct token_type: "bearer",
            access_token: nil,
            agent_token: nil,
            expires_in: nil,
            refresh_token: nil,
            id_token: nil,
            c_nonce: nil,
            token: nil,
            authorization_details: nil,
            encrypted_response: nil

  @type t :: %__MODULE__{
          token_type: String.t(),
          access_token: String.t() | nil,
          agent_token: String.t() | nil,
          id_token: String.t() | nil,
          c_nonce: String.t() | nil,
          expires_in: integer() | nil,
          refresh_token: String.t() | nil,
          token: Token.t(),
          authorization_details: map() | nil,
          encrypted_response: String.t() | nil
        }

  @spec from_token(%{
          (type :: :token | :agent_token | :preauthorized_token) => token :: Boruta.Oauth.Token.t() | String.t()
        }) :: t()
  def from_token(
        %{
          token:
            %Token{
              value: value,
              expires_at: expires_at,
              refresh_token: refresh_token,
              c_nonce: c_nonce
            } = token
        } = params
      ) do
    {:ok, expires_at} = DateTime.from_unix(expires_at)
    expires_in = DateTime.diff(expires_at, DateTime.utc_now())

    %TokenResponse{
      token: token,
      access_token: value,
      token_type: "bearer",
      expires_in: expires_in,
      refresh_token: refresh_token,
      id_token: params[:id_token] && params[:id_token].value,
      c_nonce: c_nonce,
      authorization_details: token.authorization_details
    }
  end

  def from_token(
        %{
          agent_token:
            %Token{
              value: value,
              expires_at: expires_at,
              refresh_token: refresh_token,
              c_nonce: c_nonce
            } = token
        } = params
      ) do
    {:ok, expires_at} = DateTime.from_unix(expires_at)
    expires_in = DateTime.diff(expires_at, DateTime.utc_now())

    %TokenResponse{
      token: token,
      agent_token: value,
      token_type: "bearer",
      expires_in: expires_in,
      refresh_token: refresh_token,
      id_token: params[:id_token] && params[:id_token].value,
      c_nonce: c_nonce,
      authorization_details: token.authorization_details
    }
  end

  def from_token(
        %{
          preauthorized_token:
            %Token{
              value: value,
              expires_at: expires_at,
              refresh_token: refresh_token,
              c_nonce: c_nonce
            } = token
        } = params
      ) do
    {:ok, expires_at} = DateTime.from_unix(expires_at)
    expires_in = DateTime.diff(expires_at, DateTime.utc_now())
    encrypted_response = with "" <> previous_code <- token.previous_code,
      %Token{} = token <- CodesAdapter.get_by(value: previous_code) do
      Client.Crypto.encrypt(%{
        access_token: value,
        token_type: "bearer",
        expires_in: expires_in,
        refresh_token: refresh_token,
        id_token: params[:id_token] && params[:id_token].value,
        c_nonce: c_nonce,
        authorization_details: token.authorization_details
      }, token.client_encryption_key, token.client_encryption_alg)
    else
      _ -> nil
    end

    %TokenResponse{
      token: token,
      access_token: value,
      token_type: "bearer",
      expires_in: expires_in,
      refresh_token: refresh_token,
      id_token: params[:id_token] && params[:id_token].value,
      c_nonce: c_nonce,
      authorization_details: token.authorization_details,
      encrypted_response: encrypted_response
    }
  end
end
