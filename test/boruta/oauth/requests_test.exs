defmodule Boruta.Oauth.RequestsTest do
  use ExUnit.Case, async: true

  alias Boruta.Oauth.AuthorizationCodeRequest
  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.HybridRequest
  alias Boruta.Oauth.IntrospectRequest
  alias Boruta.Oauth.PasswordRequest
  alias Boruta.Oauth.RefreshTokenRequest
  alias Boruta.Oauth.RevokeRequest
  alias Boruta.Oauth.TokenRequest

  alias Boruta.Oauth.ResourceOwner

  test "Boruta.Oauth.AuthorizationCodeRequest" do
    assert %AuthorizationCodeRequest{
      client_id: "client_id",
      redirect_uri: "http://redirect.uri",
      code: "code"
    }
  end

  test "Boruta.Oauth.CodeRequest" do
    assert %CodeRequest{
      client_id: "client_id",
      redirect_uri: "http://redirect.uri",
      resource_owner: %ResourceOwner{sub: "sub"}
    }
  end

  test "Boruta.Oauth.HybridRequest" do
    assert %HybridRequest{
      client_id: "client_id",
      redirect_uri: "http://redirect.uri",
      resource_owner: %ResourceOwner{sub: "sub"}
    }
  end

  test "Boruta.Oauth.TokenRequest" do
    assert %TokenRequest{
      client_id: "client_id",
      redirect_uri: "http://redirect.uri",
      resource_owner: %ResourceOwner{sub: "sub"}
    }
  end

  test "Boruta.Oauth.ClientCredentialsRequest" do
    assert %ClientCredentialsRequest{
      client_id: "client_id",
      client_authentication: %{type: "basic", value: "client_secret"},
    }
  end

  test "Boruta.Oauth.PasswordRequest" do
    assert %PasswordRequest{
      client_id: "client_id",
      client_authentication: %{type: "basic", value: "client_secret"},
      username: "username",
      password: "password",
    }
  end

  test "Boruta.Oauth.RefreshTokenRequest" do
    assert %RefreshTokenRequest{
      client_id: "client_id",
      client_authentication: %{type: "basic", value: "client_secret"},
      refresh_token: "refresh_token"
    }
  end

  test "Boruta.Oauth.IntrospectRequest" do
    assert %IntrospectRequest{
      client_id: "client_id",
      client_authentication: %{type: "basic", value: "client_secret"},
      token: "token"
    }
  end

  test "Boruta.Oauth.RevokeRequest" do
    assert %RevokeRequest{
      client_id: "client_id",
      client_authentication: %{type: "basic", value: "client_secret"},
      token: "token"
    }
  end
end
