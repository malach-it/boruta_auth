defmodule Boruta.Oauth.Request.Token do
  @moduledoc false

  import Boruta.Oauth.Request.Base

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
    with {:ok, request_params} <- fetch_client_authentication(request),
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
end
