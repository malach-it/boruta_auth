defmodule Boruta.Oauth.Request.Base do
  @moduledoc false

  alias Boruta.Oauth.AuthorizationCodeRequest
  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.IntrospectRequest
  alias Boruta.Oauth.PasswordRequest
  alias Boruta.Oauth.RefreshTokenRequest
  alias Boruta.Oauth.RevokeRequest
  alias Boruta.Oauth.TokenRequest

  @spec authorization_header(req_headers :: list()) ::
  {:ok, header :: String.t()} |
  {:error, :no_authorization_header}
  def authorization_header(req_headers) do
    case Enum.find(
      req_headers,
      fn (header) -> elem(header, 0) == "authorization" end
    ) do
      {"authorization", header} -> {:ok, header}
      _ -> {:error, :no_authorization_header}
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
    {:ok, %RefreshTokenRequest{
      client_id: params["client_id"],
      client_secret: params["client_secret"],
      refresh_token: params["refresh_token"],
      scope: params["scope"]
    }}
  end

  def build_request(%{"response_type" => "token"} = params) do
    {:ok, %TokenRequest{
      client_id: params["client_id"],
      redirect_uri: params["redirect_uri"],
      resource_owner: params["resource_owner"],
      state: params["state"],
      scope: params["scope"]
    }}
  end
  def build_request(%{"response_type" => "code"} = params) do
    {:ok, %CodeRequest{
      client_id: params["client_id"],
      redirect_uri: params["redirect_uri"],
      resource_owner: params["resource_owner"],
      state: params["state"],
      code_challenge: params["code_challenge"],
      code_challenge_method: params["code_challenge_method"],
      scope: params["scope"]
    }}
  end
  def build_request(%{"response_type" => "introspect"} = params) do
    {:ok, %IntrospectRequest{
      client_id: params["client_id"],
      client_secret: params["client_secret"],
      token: params["token"]
    }}
  end
  def build_request(%{"token" => _} = params) do # revoke request
    {:ok, %RevokeRequest{
      client_id: params["client_id"],
      client_secret: params["client_secret"],
      token: params["token"],
      token_type_hint: params["token_type_hint"]
    }}
  end
end
