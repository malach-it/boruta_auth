defmodule Boruta.OauthTest.RevokeTest do
  use ExUnit.Case
  use Boruta.DataCase

  import Boruta.Factory
  import Boruta.Config, only: [access_tokens: 0]
  import Mox

  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.Error
  alias Boruta.Support.ResourceOwners
  alias Boruta.Support.User

  describe "revoke request" do
    setup do
      client = insert(:client)
      resource_owner = %User{}
      token = insert(:token,
        type: "access_token",
        client_id: client.id,
        scope: "scope",
        sub: resource_owner.id
      )
      {:ok,
        client: client,
        token: token,
        resource_owner: resource_owner
      }
    end

    test "returns an error without params" do
      assert Oauth.revoke(%{}, ApplicationMock) == {:revoke_error, %Error{
        error: :invalid_request,
        error_description: "Must provide body_params.",
        status: :bad_request
      }}
    end

    test "returns an error with invalid request" do
      assert Oauth.revoke(%{body_params: %{}}, ApplicationMock) == {:revoke_error, %Error{
        error: :invalid_request,
        error_description: "Request validation failed. Required properties client_id, client_secret, token are missing at #.",
        status: :bad_request
      }}
    end

    test "returns an error with invalid client_id/secret", %{client: client} do
      %{req_headers: [{"authorization", authorization_header}]} = using_basic_auth(client.id, "bad_secret")

      assert Oauth.revoke(%{
        body_params: %{"token" => "token"},
        req_headers: [{"authorization", authorization_header}]
      }, ApplicationMock) == {:revoke_error, %Error{
        error: :invalid_client,
        error_description: "Invalid client_id or client_secret.",
        status: :unauthorized
      }}
    end

    test "revoke token if token is active", %{client: client, token: token, resource_owner: resource_owner} do
      ResourceOwners
      |> stub(:get_by, fn(_params) -> resource_owner end)
      |> stub(:persisted?, fn(_params) -> true end)
      %{req_headers: [{"authorization", authorization_header}]} = using_basic_auth(client.id, client.secret)
      case Oauth.revoke(%{
        body_params: %{"token" => token.value},
        req_headers: [{"authorization", authorization_header}]
      }, ApplicationMock) do
        {:revoke_success} ->
          assert access_tokens().get_by(value: token.value).revoked_at
        _ -> assert false
      end
    end
  end

  defp using_basic_auth(username, password) do
    authorization_header = "Basic " <> Base.encode64("#{username}:#{password}")
    %{req_headers: [{"authorization", authorization_header}]}
  end
end
