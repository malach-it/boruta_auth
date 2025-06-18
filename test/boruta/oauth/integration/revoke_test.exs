defmodule Boruta.OauthTest.RevokeTest do
  use ExUnit.Case
  use Boruta.DataCase

  import Boruta.Factory
  import Mox

  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Support.ResourceOwners
  alias Boruta.Support.User

  setup :verify_on_exit!

  describe "revoke request" do
    setup do
      client = insert(:client)
      public_revoke_client = insert(:client, public_revoke: true, confidential: true)
      user = %User{}
      resource_owner = %ResourceOwner{sub: user.id, username: user.email}

      token =
        insert(:token,
          type: "access_token",
          client: client,
          scope: "scope",
          sub: resource_owner.sub
        )

      {:ok,
       client: client,
       public_revoke_client: public_revoke_client,
       token: token,
       resource_owner: resource_owner}
    end

    test "returns an error without params" do
      assert Oauth.revoke(%Plug.Conn{body_params: %{}}, ApplicationMock) ==
               {:revoke_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request validation failed. Required properties client_id, token are missing at #.",
                  status: :bad_request
                }}
    end

    test "returns an error with invalid basic header" do
      assert Oauth.revoke(
               %Plug.Conn{
                 body_params: %{"token" => "token"},
                 req_headers: [
                   {"authorization", "Basic invalid_basic_header"},
                   {"other", "header"}
                 ]
               },
               ApplicationMock
             ) ==
               {:revoke_error,
                %Error{
                  error: :invalid_request,
                  error_description: "Given credentials are invalid.",
                  status: :bad_request
                }}
    end

    test "returns an error with invalid client_id/secret", %{client: client} do
      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client.id, "bad_secret")

      assert Oauth.revoke(
               %Plug.Conn{
                 body_params: %{"token" => "token"},
                 req_headers: [{"authorization", authorization_header}, {"other", "header"}]
               },
               ApplicationMock
             ) ==
               {:revoke_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or client_secret.",
                  status: :unauthorized
                }}
    end

    test "returns an error with invalid client_id/secret in body", %{client: client} do
      assert Oauth.revoke(
               %Plug.Conn{
                 body_params: %{
                   "token" => "token",
                   "client_id" => client.id,
                   "secret" => "bad_secret"
                 },
                 req_headers: [{"first", "header"}, {"other", "header"}]
               },
               ApplicationMock
             ) ==
               {:revoke_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or client_secret.",
                  status: :unauthorized
                }}
    end

    test "revoke token by value if token is active", %{
      client: client,
      token: token,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 3, fn _params -> {:ok, resource_owner} end)

      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client.id, client.secret)

      case Oauth.revoke(
             %Plug.Conn{
               body_params: %{"token" => token.value},
               req_headers: [{"authorization", authorization_header}]
             },
             ApplicationMock
           ) do
        {:revoke_success} ->
          assert Boruta.AccessTokensAdapter.get_by(value: token.value).revoked_at

        _ ->
          assert false
      end
    end

    test "revoke token by refresh token if token is active", %{
      client: client,
      token: token,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 3, fn _params -> {:ok, resource_owner} end)

      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client.id, client.secret)

      case Oauth.revoke(
             %Plug.Conn{
               body_params: %{"token" => token.refresh_token},
               req_headers: [{"authorization", authorization_header}]
             },
             ApplicationMock
           ) do
        {:revoke_success} ->
          assert Boruta.AccessTokensAdapter.get_by(value: token.value).revoked_at

        _ ->
          assert false
      end
    end

    test "revoke token by value if token is active with token hint", %{
      client: client,
      token: token,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 3, fn _params -> {:ok, resource_owner} end)

      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client.id, client.secret)

      case Oauth.revoke(
             %Plug.Conn{
               body_params: %{"token" => token.value, "token_type_hint" => "refresh_token"},
               req_headers: [{"authorization", authorization_header}]
             },
             ApplicationMock
           ) do
        {:revoke_success} ->
          assert Boruta.AccessTokensAdapter.get_by(value: token.value).revoked_at

        _ ->
          assert false
      end
    end

    test "revoke token by refresh token if token is active with token hint", %{
      client: client,
      token: token,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 3, fn _params -> {:ok, resource_owner} end)

      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client.id, client.secret)

      case Oauth.revoke(
             %Plug.Conn{
               body_params: %{
                 "token" => token.refresh_token,
                 "token_type_hint" => "refresh_token"
               },
               req_headers: [{"authorization", authorization_header}]
             },
             ApplicationMock
           ) do
        {:revoke_success} ->
          assert Boruta.AccessTokensAdapter.get_by(value: token.value).revoked_at

        _ ->
          assert false
      end
    end

    test "revoke token if client has public revocation", %{
      public_revoke_client: client,
      token: token,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      assert {:revoke_success} =
               Oauth.revoke(
                 %Plug.Conn{
                   body_params: %{"token" => token.value, "client_id" => client.id}
                 },
                 ApplicationMock
               )
    end
  end

  defp using_basic_auth(username, password) do
    authorization_header = "Basic " <> Base.encode64("#{username}:#{password}")
    %{req_headers: [{"authorization", authorization_header}]}
  end
end
