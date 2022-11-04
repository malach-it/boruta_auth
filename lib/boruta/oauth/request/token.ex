defmodule Boruta.Oauth.Request.Token do
  @moduledoc false

  import Boruta.Oauth.Request.Base

  alias Boruta.BasicAuth
  alias Boruta.Oauth.AuthorizationCodeRequest
  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.PasswordRequest
  alias Boruta.Oauth.Validator

  @spec request(conn :: Plug.Conn.t() | map()) ::
          {:error,
           %Error{
             :error => :invalid_request,
             :error_description => String.t(),
             :format => nil,
             :redirect_uri => nil,
             :status => :bad_request
           }}
          | {:ok,
             oauth_request ::
               AuthorizationCodeRequest.t()
               | ClientCredentialsRequest.t()
               | PasswordRequest.t()}
  def request(request) do
    with {:ok, request_params} <- fetch_request_params(request),
         {:ok, params} <- Validator.validate(:token, request_params) do
      build_request(params)
    else
      {:error, error_description} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :invalid_request,
           error_description: error_description
         }}
    end
  end

  defp fetch_request_params(%{
         body_params:
           %{
             "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
             "client_assertion" => client_assertion
           } = body_params
       }) do
    case Joken.peek_claims(client_assertion) do
      {:ok, claims} ->
        with :ok <- check_issuer(claims),
             :ok <- check_audience(claims),
             :ok <- check_expiration(claims) do
          request_params = Enum.into(body_params, %{"client_id" => claims["sub"]})

          {:ok, request_params}
        end

      {:error, _error} ->
        {:error, "Could not decode client assertion JWT."}
    end
  end

  defp fetch_request_params(%{
         req_headers: req_headers,
         body_params: %{} = body_params
       }) do
    with {:ok, authorization_header} <- authorization_header(req_headers),
         {:ok, [client_id, client_secret]} <- BasicAuth.decode(authorization_header) do
      request_params =
        Enum.into(body_params, %{"client_id" => client_id, "client_secret" => client_secret})

      {:ok, request_params}
    else
      {:error, :no_authorization_header} -> {:ok, body_params}
      {:error, reason} -> {:error, reason}
    end
  end

  defp check_issuer(%{"iss" => _iss}), do: :ok

  defp check_issuer(_claims),
    do: {:error, "Client assertion iss claim not found in client assertion JWT."}

  defp check_audience(%{"aud" => aud}) do
    server_issuer = Boruta.Config.issuer()

    case aud == server_issuer do
      true ->
        :ok

      false ->
        {:error,
         "Client assertion aud claim does not match with authorization server (#{server_issuer})."}
    end
  end

  defp check_audience(_claims),
    do: {:error, "Client assertion aud claim not found in client assertion JWT."}

  defp check_expiration(%{"exp" => _exp}), do: :ok

  defp check_expiration(_claims),
    do: {:error, "Client assertion exp claim not found in client assertion JWT."}
end
