defmodule Boruta.Oauth.AuthorizeResponse do
  @moduledoc """
  Authorize response
  """

  defstruct type: nil,
            redirect_uri: nil,
            code: nil,
            id_token: nil,
            access_token: nil,
            expires_in: nil,
            state: nil,
            code_challenge: nil,
            code_challenge_method: nil

  @type t :: %__MODULE__{
          type: String.t(),
          redirect_uri: String.t(),
          code: String.t(),
          id_token: String.t() | nil,
          access_token: String.t() | nil,
          expires_in: integer(),
          state: String.t(),
          code_challenge: String.t(),
          code_challenge_method: String.t()
        }

  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Token

  @spec from_tokens(%{
          (type :: :code | :token | :id_token) => token :: Boruta.Oauth.Token.t() | String.t()
        }) :: t()
  def from_tokens(
        %{
          code: %Token{
            type: type,
            expires_at: expires_at,
            value: value,
            redirect_uri: redirect_uri,
            state: state,
            code_challenge: code_challenge,
            code_challenge_method: code_challenge_method
          }
        } = params
      ) do
    {:ok, expires_at} = DateTime.from_unix(expires_at)
    expires_in = DateTime.diff(expires_at, DateTime.utc_now())

    %AuthorizeResponse{
      type: type,
      redirect_uri: redirect_uri,
      code: value,
      id_token: params[:id_token],
      access_token: params[:token] && params[:token].value,
      expires_in: expires_in,
      state: state,
      code_challenge: code_challenge,
      code_challenge_method: code_challenge_method
    }
  end

  def from_tokens(%{
        token: %Token{
          type: type,
          expires_at: expires_at,
          value: value,
          redirect_uri: redirect_uri,
          state: state,
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method
        }
      }) do
    {:ok, expires_at} = DateTime.from_unix(expires_at)
    expires_in = DateTime.diff(expires_at, DateTime.utc_now())

    %AuthorizeResponse{
      type: type,
      redirect_uri: redirect_uri,
      access_token: value,
      expires_in: expires_in,
      state: state,
      code_challenge: code_challenge,
      code_challenge_method: code_challenge_method
    }
  end
end
