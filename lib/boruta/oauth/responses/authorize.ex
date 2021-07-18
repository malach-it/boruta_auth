defmodule Boruta.Oauth.AuthorizeResponse do
  @moduledoc """
  Authorize response
  """

  alias Boruta.Oauth.Error

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
          type: :token | :code | :hybrid,
          redirect_uri: String.t(),
          expires_in: integer(),
          code: String.t(),
          id_token: String.t() | nil,
          access_token: String.t() | nil,
          state: String.t() | nil,
          code_challenge: String.t() | nil,
          code_challenge_method: String.t() | nil
        }

  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Token

  @spec from_tokens(%{
          (type :: :code | :token | :id_token) => token :: Boruta.Oauth.Token.t() | String.t()
        }) :: t()
  def from_tokens(
        %{
          code: %Token{
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

    type =
      case is_nil(params[:id_token] || params[:token]) do
        false -> :hybrid
        true -> :code
      end

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

  def from_tokens(
        %{
          token: %Token{
            expires_at: expires_at,
            value: value,
            redirect_uri: redirect_uri,
            state: state
          }
        } = params
      ) do
    {:ok, expires_at} = DateTime.from_unix(expires_at)
    expires_in = DateTime.diff(expires_at, DateTime.utc_now())

    %AuthorizeResponse{
      type: :token,
      redirect_uri: redirect_uri,
      access_token: value,
      id_token: params[:id_token] && params[:id_token].value,
      expires_in: expires_in,
      state: state
    }
  end

  def from_tokens(%{
        id_token: %Token{
          value: id_token,
          redirect_uri: redirect_uri,
          state: state
        }
      }) do
    %AuthorizeResponse{
      type: :token,
      redirect_uri: redirect_uri,
      id_token: id_token,
      state: state
    }
  end

  def from_tokens(_) do
    {:error,
     %Error{
       status: :bad_request,
       error: :invalid_request,
       error_description:
         "Neither code, nor access_token, nor id_token could be created with given parameters."
     }}
  end
end
