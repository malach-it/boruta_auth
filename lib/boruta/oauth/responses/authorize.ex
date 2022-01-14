defmodule Boruta.Oauth.AuthorizeResponse do
  @moduledoc """
  Response returned in case of authorization request success. Provides utilities and mandatory data needed to respond to the authorize part of implicit, code and hybrid flows.
  """

  alias Boruta.Oauth.Error

  @enforce_keys [:type, :redirect_uri]
  defstruct type: nil,
            redirect_uri: nil,
            code: nil,
            id_token: nil,
            access_token: nil,
            expires_in: nil,
            state: nil,
            code_challenge: nil,
            code_challenge_method: nil,
            token_type: nil

  @type t :: %__MODULE__{
          type: :token | :code | :hybrid,
          redirect_uri: String.t(),
          expires_in: integer(),
          code: String.t() | nil,
          id_token: String.t() | nil,
          access_token: String.t() | nil,
          state: String.t() | nil,
          code_challenge: String.t() | nil,
          code_challenge_method: String.t() | nil,
          token_type: String.t() | nil
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
      case is_hybrid?(params) do
        true -> :hybrid
        false -> :code
      end

    %AuthorizeResponse{
      type: type,
      redirect_uri: redirect_uri,
      code: value,
      id_token: params[:id_token] && params[:id_token].value,
      access_token: params[:token] && params[:token].value,
      expires_in: expires_in,
      state: state,
      code_challenge: code_challenge,
      code_challenge_method: code_challenge_method,
      token_type: if(is_hybrid?(params), do: "bearer")
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
      state: state,
      token_type: "bearer"
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

  defp is_hybrid?(params) do
    !is_nil(params[:id_token] || params[:token])
  end

  @spec redirect_to_url(__MODULE__.t()) :: url :: String.t()
  def redirect_to_url(%__MODULE__{} = response) do
    query_params = query_params(response)
    url(response, query_params)
  end

  defp query_params(%__MODULE__{
         access_token: access_token,
         code: code,
         id_token: id_token,
         expires_in: expires_in,
         state: state,
         token_type: token_type
       }) do
    %{
      code: code,
      id_token: id_token,
      access_token: access_token,
      expires_in: expires_in,
      state: state,
      token_type: token_type
    }
    |> Enum.map(fn {param_type, value} ->
      value && {param_type, value}
    end)
    |> Enum.reject(&is_nil/1)
    |> URI.encode_query()
  end

  defp url(%__MODULE__{type: :token, redirect_uri: redirect_uri}, query_params),
    do: "#{redirect_uri}##{query_params}"

  defp url(%__MODULE__{type: :code, redirect_uri: redirect_uri}, query_params),
    do: "#{redirect_uri}?#{query_params}"

  defp url(%__MODULE__{type: :hybrid, redirect_uri: redirect_uri}, query_params),
    do: "#{redirect_uri}##{query_params}"
end
