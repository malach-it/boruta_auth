defmodule Boruta.Oauth.Request.Base do
  @moduledoc false

  alias Boruta.Oauth.AuthorizationCodeRequest
  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.HybridRequest
  alias Boruta.Oauth.IntrospectRequest
  alias Boruta.Oauth.PasswordRequest
  alias Boruta.Oauth.RefreshTokenRequest
  alias Boruta.Oauth.RevokeRequest
  alias Boruta.Oauth.TokenRequest

  @spec authorization_header(req_headers :: list()) ::
          {:ok, header :: String.t()}
          | {:error, :no_authorization_header}
  def authorization_header(req_headers) do
    case List.keyfind(req_headers, "authorization", 0) do
      nil -> {:error, :no_authorization_header}
      {"authorization", header} -> {:ok, header}
    end
  end

  def build_request(%{"grant_type" => "client_credentials"} = params) do
    {:ok, %ClientCredentialsRequest{
      client_id: params["client_id"],
      client_secret: params["client_secret"],
      scope: params["scope"]
    }}
  end

  def build_request(%{"grant_type" => "password"} = params) do
    {:ok, %PasswordRequest{
      client_id: params["client_id"],
      client_secret: params["client_secret"],
      username: params["username"],
      password: params["password"],
      scope: params["scope"]
    }}
  end

  def build_request(%{"grant_type" => "authorization_code"} = params) do
    {:ok, %AuthorizationCodeRequest{
      client_id: params["client_id"],
      code: params["code"],
      redirect_uri: params["redirect_uri"],
      code_verifier: params["code_verifier"]
    }}
  end

  def build_request(%{"grant_type" => "refresh_token"} = params) do
    {:ok,
     %RefreshTokenRequest{
       client_id: params["client_id"],
       client_secret: params["client_secret"],
       refresh_token: params["refresh_token"],
       scope: params["scope"]
     }}
  end

  def build_request(%{"response_type" => "code"} = params) do
    {:ok,
     %CodeRequest{
       client_id: params["client_id"],
       redirect_uri: params["redirect_uri"],
       resource_owner: params["resource_owner"],
       state: params["state"],
       nonce: params["nonce"],
       code_challenge: params["code_challenge"],
       code_challenge_method: params["code_challenge_method"],
       scope: params["scope"]
     }}
  end

  def build_request(%{"response_type" => "introspect"} = params) do
    {:ok,
     %IntrospectRequest{
       client_id: params["client_id"],
       client_secret: params["client_secret"],
       token: params["token"]
     }}
  end

  def build_request(%{"response_type" => response_type} = params) do
    response_types = String.split(response_type, " ")

    case Enum.member?(response_types, "code") do
      true ->
        {:ok,
         %HybridRequest{
           response_types: response_types,
           client_id: params["client_id"],
           redirect_uri: params["redirect_uri"],
           resource_owner: params["resource_owner"],
           state: params["state"],
           code_challenge: params["code_challenge"],
           code_challenge_method: params["code_challenge_method"],
           scope: params["scope"],
           nonce: params["nonce"],
           prompt: params["prompt"]
         }}

      false ->
        {:ok,
         %TokenRequest{
           response_types: response_types,
           client_id: params["client_id"],
           redirect_uri: params["redirect_uri"],
           resource_owner: params["resource_owner"],
           state: params["state"],
           scope: params["scope"],
           nonce: params["nonce"],
           prompt: params["prompt"]
         }}
    end
  end

  # revoke request
  def build_request(%{"token" => _} = params) do
    {:ok,
     %RevokeRequest{
       client_id: params["client_id"],
       client_secret: params["client_secret"],
       token: params["token"],
       token_type_hint: params["token_type_hint"]
     }}
  end
end
