defmodule Boruta.Oauth.AuthorizeResponse do
  @moduledoc """
  Response returned in case of authorization request success. Provides utilities and mandatory data needed to respond to the authorize part of implicit, code and hybrid flows.
  """

  alias Boruta.Oauth.Error

  @enforce_keys [:type, :redirect_uri]
  defstruct access_token: nil,
            code: nil,
            code_challenge: nil,
            code_challenge_method: nil,
            expires_in: nil,
            id_token: nil,
            redirect_uri: nil,
            response_mode: nil,
            state: nil,
            token_type: nil,
            type: nil

  @type t :: %__MODULE__{
          access_token: String.t() | nil,
          code: String.t() | nil,
          code_challenge: String.t() | nil,
          code_challenge_method: String.t() | nil,
          expires_in: integer(),
          id_token: String.t() | nil,
          redirect_uri: String.t(),
          response_mode: String.t() | nil,
          state: String.t() | nil,
          token_type: String.t() | nil,
          type: :token | :code | :hybrid
        }

  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.HybridRequest
  alias Boruta.Oauth.Token
  alias Boruta.Oauth.TokenRequest

  @spec from_tokens(
          %{
            (type :: :code | :token | :id_token) => token :: Boruta.Oauth.Token.t() | String.t()
          },
          request :: CodeRequest.t() | TokenRequest.t() | HybridRequest.t()
        ) :: t()
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
        } = params,
        request
      ) do
    {:ok, expires_at} = DateTime.from_unix(expires_at)
    expires_in = DateTime.diff(expires_at, DateTime.utc_now())

    type =
      case hybrid?(params) do
        true -> :hybrid
        false -> :code
      end

    response_mode =
      case request.__struct__ do
        HybridRequest -> request.response_mode
        _ -> nil
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
      token_type: if(has_token_type?(params), do: "bearer"),
      response_mode: response_mode
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
        } = params,
        _request
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

  def from_tokens(
        %{
          id_token: %Token{
            value: id_token,
            redirect_uri: redirect_uri,
            state: state
          }
        },
        _request
      ) do
    %AuthorizeResponse{
      type: :token,
      redirect_uri: redirect_uri,
      id_token: id_token,
      state: state
    }
  end

  def from_tokens(_params, _request) do
    {:error,
     %Error{
       status: :bad_request,
       error: :invalid_request,
       error_description:
         "Neither code, nor access_token, nor id_token could be created with given parameters."
     }}
  end

  defp has_token_type?(params) do
    hybrid?(params) && has_access_token?(params)
  end

  defp hybrid?(params) do
    !is_nil(params[:id_token] || params[:token])
  end

  defp has_access_token?(params) do
    Map.has_key?(params, :token)
  end

  @spec redirect_to_url(__MODULE__.t()) :: url :: String.t()
  def redirect_to_url(%__MODULE__{} = response) do
    params = params(response)
    url(response, params)
  end

  defp params(%__MODULE__{
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
    |> Enum.into(%{})
  end

  defp url(%__MODULE__{type: :token, redirect_uri: redirect_uri}, params) do
    add_fragment_to_redirect_uri(redirect_uri, params)
  end

  defp url(%__MODULE__{type: :code, redirect_uri: redirect_uri}, params) do
    add_query_to_redirect_uri(redirect_uri, params)
  end

  defp url(
         %__MODULE__{type: :hybrid, response_mode: "query", redirect_uri: redirect_uri},
         params
       ) do
    add_query_to_redirect_uri(redirect_uri, params)
  end

  defp url(
         %__MODULE__{type: :hybrid, response_mode: "fragment", redirect_uri: redirect_uri},
         params
       ) do
    add_fragment_to_redirect_uri(redirect_uri, params)
  end

  # fallback to fragment since it is the hybrid default response mode
  defp url(
         %__MODULE__{type: :hybrid, response_mode: nil, redirect_uri: redirect_uri},
         params
       ) do
    add_fragment_to_redirect_uri(redirect_uri, params)
  end

  defp add_query_to_redirect_uri(redirect_uri, params) do
    redirect_uri = URI.parse(redirect_uri)

    query =
      (redirect_uri.query || "")
      |> URI.decode_query()
      |> Map.merge(params)
      |> URI.encode_query()

    URI.to_string(%{redirect_uri | query: query})
  end

  defp add_fragment_to_redirect_uri(redirect_uri, params) do
    redirect_uri = URI.parse(redirect_uri)
    fragment = URI.encode_query(params)

    URI.to_string(%{redirect_uri | fragment: fragment})
  end
end
