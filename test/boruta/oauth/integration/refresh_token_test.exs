defmodule Boruta.OauthTest.RefreshTokenTest do
  use ExUnit.Case
  use Boruta.DataCase

  import Boruta.Factory
  import Mox

  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.TokenResponse
  alias Boruta.Support.ResourceOwners

  describe "refresh_token" do
    setup do
      stub(ResourceOwners, :get_by, fn (_params) -> {:error, "No resource owner."} end)
      client = insert(:client)
      client_without_grant_type = insert(:client, supported_grant_types: [])
      expired_access_token = insert(
        :token,
        type: "access_token",
        refresh_token: Boruta.TokenGenerator.generate(),
        client: client,
        redirect_uri: List.first(client.redirect_uris),
        expires_at: :os.system_time(:seconds) - 10
      )
      {:ok, revoked_at} = (:os.system_time(:seconds) - 10) |> DateTime.from_unix()
      revoked_access_token = insert(
        :token,
        type: "access_token",
        refresh_token: Boruta.TokenGenerator.generate(),
        client: client,
        redirect_uri: List.first(client.redirect_uris),
        revoked_at: revoked_at
      )
      access_token = insert(
        :token,
        type: "access_token",
        refresh_token: Boruta.TokenGenerator.generate(),
        client: client,
        redirect_uri: List.first(client.redirect_uris),
        expires_at: :os.system_time(:seconds) + 10,
        scope: "scope"
      )
      other_client_access_token = insert(
        :token,
        type: "access_token",
        refresh_token: Boruta.TokenGenerator.generate(),
        client: insert(:client),
        redirect_uri: List.first(client.redirect_uris),
        expires_at: :os.system_time(:seconds) + 10,
        scope: "scope"
      )
      {:ok,
        client: client,
        client_without_grant_type: client_without_grant_type,
        expired_access_token: expired_access_token,
        revoked_access_token: revoked_access_token,
        access_token: access_token,
        other_client_access_token: other_client_access_token
      }
    end

    test "returns an error if `grant_type` is 'refresh_token' and schema is invalid" do
      assert Oauth.token(%Plug.Conn{body_params: %{"grant_type" => "refresh_token"}}, ApplicationMock) == {:token_error, %Error{
        error: :invalid_request,
        error_description: "Request body validation failed. Required property refresh_token is missing at #.",
        status: :bad_request
      }}
    end

    test "returns an error if client is invalid" do
      %{req_headers: [{"authorization", authorization_header}]} = using_basic_auth("6a2f41a3-c54c-fce8-32d2-0324e1c32e22", "test")
      assert Oauth.token(%Plug.Conn{
        body_params: %{"grant_type" => "refresh_token", "refresh_token" => "refresh_token"},
        req_headers: [{"authorization", authorization_header}]
      }, ApplicationMock) == {:token_error, %Error{
        error: :invalid_client,
        error_description: "Invalid client_id or client_secret.",
        status: :unauthorized
      }}
    end

    test "returns an error if refresh_token is invalid", %{client: client} do
      %{req_headers: [{"authorization", authorization_header}]} = using_basic_auth(client.id, client.secret)
      assert Oauth.token(%Plug.Conn{
        body_params: %{"grant_type" => "refresh_token", "refresh_token" => "bad_refresh_token"},
        req_headers: [{"authorization", authorization_header}]
      }, ApplicationMock) == {:token_error, %Error{
        error: :invalid_refresh_token,
        error_description: "Provided refresh token is incorrect.",
        status: :bad_request
      }}
    end

    test "returns an error if access_token associated is expired", %{client: client, expired_access_token: token} do
      %{req_headers: [{"authorization", authorization_header}]} = using_basic_auth(client.id, client.secret)
      assert Oauth.token(%Plug.Conn{
        body_params: %{"grant_type" => "refresh_token", "refresh_token" => token.refresh_token},
        req_headers: [{"authorization", authorization_header}]
      }, ApplicationMock) == {:token_error, %Error{
        error: :invalid_refresh_token,
        error_description: "Token expired.",
        status: :bad_request
      }}
    end

    test "returns an error if access_token associated belongs to an other client", %{
      client: client,
      other_client_access_token: token
    } do
      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client.id, client.secret)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "refresh_token",
                   "refresh_token" => token.refresh_token
                 },
                 req_headers: [{"authorization", authorization_header}]
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given refresh token is invalid.",
                  status: :bad_request
                }}
    end

    test "returns an error if access_token associated is revoked", %{
      client: client,
      revoked_access_token: token
    } do
      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client.id, client.secret)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "refresh_token",
                   "refresh_token" => token.refresh_token
                 },
                 req_headers: [{"authorization", authorization_header}]
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_refresh_token,
                  error_description: "Token revoked.",
                  status: :bad_request
                }}
    end

    test "returns an error if scope is unknown or unauthorized", %{client: client, access_token: token} do
      ResourceOwners
      |> stub(:authorized_scopes, fn(_resource_owner) -> [] end)
      %{req_headers: [{"authorization", authorization_header}]} = using_basic_auth(client.id, client.secret)
      assert Oauth.token(%Plug.Conn{
        body_params: %{"grant_type" => "refresh_token", "refresh_token" => token.refresh_token, "scope" => "bad_scope"},
        req_headers: [{"authorization", authorization_header}]
      }, ApplicationMock) == {:token_error, %Error{
        error: :invalid_scope,
        error_description: "Given scopes are unknown or unauthorized.",
        status: :bad_request
      }}
    end

    test "returns an error if grant type is not allowed by client", %{client_without_grant_type: client, access_token: token} do
      %{req_headers: [{"authorization", authorization_header}]} = using_basic_auth(client.id, client.secret)
      assert Oauth.token(%Plug.Conn{
        body_params: %{"grant_type" => "refresh_token", "refresh_token" => token.refresh_token, "scope" => "bad_scope"},
        req_headers: [{"authorization", authorization_header}]
      }, ApplicationMock) == {:token_error, %Error{
        error: :unsupported_grant_type,
        error_description: "Client do not support given grant type.",
        status: :bad_request
      }}
    end

    test "returns token", %{client: client, access_token: token} do
      ResourceOwners
      |> stub(:authorized_scopes, fn(_resource_owner) -> [] end)
      %{req_headers: [{"authorization", authorization_header}]} = using_basic_auth(client.id, client.secret)
      case Oauth.token(
        %Plug.Conn{
          body_params: %{"grant_type" => "refresh_token", "refresh_token" => token.refresh_token, "scope" => "scope"},
          req_headers: [{"authorization", authorization_header}]
        },
        ApplicationMock
      ) do
        {:token_success,
          %TokenResponse{
            token_type: token_type,
            access_token: access_token,
            expires_in: expires_in,
            refresh_token: refresh_token
          }
        } ->
          assert token_type == "bearer"
          assert access_token
          assert expires_in
          assert refresh_token
        _ ->
          assert false
      end
    end
  end

  defp using_basic_auth(username, password) do
    authorization_header = "Basic " <> Base.encode64("#{username}:#{password}")
    %{req_headers: [{"authorization", authorization_header}]}
  end
end
