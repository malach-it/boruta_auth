defmodule Boruta.OauthTest.ClientCredentialsGrantTest do
  use ExUnit.Case
  use Boruta.DataCase

  import Boruta.Factory

  alias Boruta.Ecto.ScopeStore
  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.TokenResponse

  describe "client credentials grant" do
    setup do
      client = insert(:client)
      client_without_grant_type = insert(:client, supported_grant_types: [])

      client_with_scope =
        insert(:client,
          authorize_scope: true,
          authorized_scopes: [
            insert(:scope, name: "public", public: true),
            insert(:scope, name: "private", public: false)
          ]
        )

      {:ok,
       client: client,
       client_with_scope: client_with_scope,
       client_without_grant_type: client_without_grant_type}
    end

    test "returns an error if `grant_type` is 'client_credentials' and schema is invalid" do
      assert Oauth.token(
               %Plug.Conn{body_params: %{"grant_type" => "client_credentials"}},
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request body validation failed. Required property client_id is missing at #.",
                  status: :bad_request
                }}
    end

    test "returns an error if client_id/secret are invalid" do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "client_credentials",
                   "client_id" => "6a2f41a3-c54c-fce8-32d2-0324e1c32e22",
                   "client_secret" => "client_secret"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or client_secret.",
                  status: :unauthorized
                }}
    end

    test "returns an error if secret is invalid", %{client: client} do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "client_credentials",
                   "client_id" => client.id,
                   "client_secret" => "bad_client_secret"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or client_secret.",
                  status: :unauthorized
                }}
    end

    test "returns a token if client_id/scret are valid", %{client: client} do
      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                access_token: access_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "client_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert access_token
      assert expires_in
      assert refresh_token
    end

    test "returns a token with public scope", %{client: client} do
      given_scope = "public"

      assert {:token_success,
       %TokenResponse{
         token_type: token_type,
         access_token: access_token,
         expires_in: expires_in,
         refresh_token: refresh_token
       }} =
        Oauth.token(
          %Plug.Conn{
            body_params: %{
              "grant_type" => "client_credentials",
              "client_id" => client.id,
              "client_secret" => client.secret,
              "scope" => given_scope
            }
          },
          ApplicationMock
        )

      assert token_type == "bearer"
      assert access_token
      assert expires_in
      assert refresh_token
    end

    test "returns a token with public scope (from cache)", %{client: client} do
      given_scope = "public"
      ScopeStore.put_public([%Scope{name: "public"}])

      assert {:token_success,
       %TokenResponse{
         token_type: token_type,
         access_token: access_token,
         expires_in: expires_in,
         refresh_token: refresh_token
       }} =
        Oauth.token(
          %Plug.Conn{
            body_params: %{
              "grant_type" => "client_credentials",
              "client_id" => client.id,
              "client_secret" => client.secret,
              "scope" => given_scope
            }
          },
          ApplicationMock
        )

      assert token_type == "bearer"
      assert access_token
      assert expires_in
      assert refresh_token
    end

    test "returns an error with private scope", %{client: client} do
      given_scope = "private"

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "client_credentials",
                   "client_id" => client.id,
                   "client_secret" => client.secret,
                   "scope" => given_scope
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Boruta.Oauth.Error{
                  error: :invalid_scope,
                  error_description: "Given scopes are unknown or unauthorized.",
                  format: nil,
                  redirect_uri: nil,
                  status: :bad_request
                }}
    end

    test "returns a token if scope is authorized", %{client_with_scope: client} do
      %{name: given_scope} = List.first(client.authorized_scopes)

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                access_token: access_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "client_credentials",
                     "client_id" => client.id,
                     "client_secret" => client.secret,
                     "scope" => given_scope
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert access_token
      assert expires_in
      assert refresh_token
    end

    test "returns an error if scopes are unknown or unauthorized", %{client_with_scope: client} do
      given_scope = "bad_scope"

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "client_credentials",
                   "client_id" => client.id,
                   "client_secret" => client.secret,
                   "scope" => given_scope
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_scope,
                  error_description: "Given scopes are unknown or unauthorized.",
                  status: :bad_request
                }}
    end

    test "returns an error if grant type is not allowed", %{client_without_grant_type: client} do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "client_credentials",
                   "client_id" => client.id,
                   "client_secret" => client.secret,
                   "scope" => ""
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :unsupported_grant_type,
                  error_description: "Client do not support given grant type.",
                  status: :bad_request
                }}
    end
  end
end
