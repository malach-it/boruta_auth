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
end
