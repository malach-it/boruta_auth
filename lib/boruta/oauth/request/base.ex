defmodule Boruta.Oauth.Request.Base do
  @moduledoc false

  alias Boruta.BasicAuth
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
    {:ok,
     %ClientCredentialsRequest{
       client_id: params["client_id"],
       client_authentication: client_authentication_from_params(params),
       scope: params["scope"]
     }}
  end

  def build_request(%{"grant_type" => "password"} = params) do
    {:ok,
     %PasswordRequest{
       client_id: params["client_id"],
       client_authentication: client_authentication_from_params(params),
       username: params["username"],
       password: params["password"],
       scope: params["scope"]
     }}
  end

  def build_request(%{"grant_type" => "authorization_code"} = params) do
    {:ok,
     %AuthorizationCodeRequest{
       client_id: params["client_id"],
       client_authentication: client_authentication_from_params(params),
       code: params["code"],
       redirect_uri: params["redirect_uri"],
       code_verifier: params["code_verifier"]
     }}
  end

  def build_request(%{"grant_type" => "refresh_token"} = params) do
    {:ok,
     %RefreshTokenRequest{
       client_id: params["client_id"],
       client_authentication: client_authentication_from_params(params),
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
       prompt: params["prompt"],
       code_challenge: params["code_challenge"],
       code_challenge_method: params["code_challenge_method"],
       scope: params["scope"]
     }}
  end

  def build_request(%{"response_type" => "introspect"} = params) do
    {:ok,
     %IntrospectRequest{
       client_id: params["client_id"],
       client_authentication: client_authentication_from_params(params),
       token: params["token"]
     }}
  end

  def build_request(%{"response_type" => response_type} = params) do
    response_types = String.split(response_type, " ")

    case Enum.member?(response_types, "code") do
      true ->
        {:ok,
         %HybridRequest{
           client_id: params["client_id"],
           code_challenge: params["code_challenge"],
           code_challenge_method: params["code_challenge_method"],
           nonce: params["nonce"],
           prompt: params["prompt"],
           redirect_uri: params["redirect_uri"],
           resource_owner: params["resource_owner"],
           response_mode: params["response_mode"],
           response_types: response_types,
           scope: params["scope"],
           state: params["state"]
         }}

      false ->
        {:ok,
         %TokenRequest{
           client_id: params["client_id"],
           nonce: params["nonce"],
           prompt: params["prompt"],
           redirect_uri: params["redirect_uri"],
           resource_owner: params["resource_owner"],
           response_types: response_types,
           scope: params["scope"],
           state: params["state"]
         }}
    end
  end

  # revoke request
  def build_request(%{"token" => _} = params) do
    {:ok,
     %RevokeRequest{
       client_id: params["client_id"],
       client_authentication: client_authentication_from_params(params),
       token: params["token"],
       token_type_hint: params["token_type_hint"]
     }}
  end

  def fetch_client_authentication(%{
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
          request_params =
            Enum.into(body_params, %{
              "client_id" => claims["sub"],
              "client_authentication" => %{"type" => "jwt", "value" => client_assertion}
            })

          {:ok, request_params}
        end

      {:error, _error} ->
        {:error, "Could not decode client assertion JWT."}
    end
  end

  def fetch_client_authentication(%{
        req_headers: req_headers,
        body_params: %{} = body_params
      }) do
    with {:ok, authorization_header} <- authorization_header(req_headers),
         {:ok, [client_id, client_secret]} <- BasicAuth.decode(authorization_header) do
      request_params =
        Enum.into(body_params, %{
          "client_id" => client_id,
          "client_authentication" => %{"type" => "basic", "value" => client_secret}
        })

      {:ok, request_params}
    else
      {:error, :no_authorization_header} ->
        {:ok,
         Enum.into(body_params, %{
           "client_authentication" => %{"type" => "post", "value" => body_params["client_secret"]}
         })}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp check_issuer(%{"iss" => _iss}), do: :ok

  defp check_issuer(_claims),
    do: {:error, "Client assertion iss claim not found in client assertion JWT."}

  defp check_audience(%{"aud" => aud}) do
    server_issuer = Boruta.Config.issuer()

    case aud =~ ~r/^#{server_issuer}/ do
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

  defp client_authentication_from_params(%{"client_authentication" => client_authentication}) do
    %{type: client_authentication["type"], value: client_authentication["value"]}
  end
end
