defmodule Boruta.OauthTest.IntrospectTest do
  use ExUnit.Case
  use Boruta.DataCase

  import Boruta.Factory
  import Mox

  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.IntrospectResponse
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Support.ResourceOwners
  alias Boruta.Support.User

  describe "introspect request" do
    setup do
      client = insert(:client)
      resource_owner = %User{}
      token = insert(
        :token,
        type: "access_token",
        client: client,
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
      assert Oauth.introspect(%{}, ApplicationMock) == {:introspect_error, %Error{
        error: :invalid_request,
        error_description: "Must provide body_params.",
        status: :bad_request
      }}
    end

    test "returns an error with invalid request" do
      assert Oauth.introspect(%{body_params: %{}}, ApplicationMock) == {:introspect_error, %Error{
        error: :invalid_request,
        error_description: "Request validation failed. Required properties client_id, client_secret, token are missing at #.",
        status: :bad_request
      }}
    end

    test "returns an error with invalid client_id/secret", %{client: client} do
      %{req_headers: [{"authorization", authorization_header}]} = using_basic_auth(client.id, "bad_secret")

      assert Oauth.introspect(%{
        body_params: %{"token" => "token"},
        req_headers: [{"authorization", authorization_header}]
      }, ApplicationMock) == {:introspect_error, %Error{
        error: :invalid_client,
        error_description: "Invalid client_id or client_secret.",
        status: :unauthorized
      }}
    end

    test "returns an inactive token if token is inactive", %{client: client} do
      %{req_headers: [{"authorization", authorization_header}]} = using_basic_auth(client.id, client.secret)

      assert Oauth.introspect(%{
        body_params: %{"token" => "token"},
        req_headers: [{"authorization", authorization_header}]
      }, ApplicationMock) == {:introspect_success,
        %IntrospectResponse{
          active: false,
          client_id: nil,
          exp: nil,
          iat: nil,
          iss: "boruta",
          scope: nil,
          sub: nil,
          username: nil
        }
      }
    end

    test "returns a token introspected if token is active", %{client: client, token: token, resource_owner: resource_owner} do
      ResourceOwners
      |> stub(:get_by, fn(_params) -> {:ok, %ResourceOwner{sub: resource_owner.id, username: resource_owner.email}} end)
      %{req_headers: [{"authorization", authorization_header}]} = using_basic_auth(client.id, client.secret)
      case Oauth.introspect(%{
        body_params: %{"token" => token.value},
        req_headers: [{"authorization", authorization_header}]
      }, ApplicationMock) do
        {:introspect_success, %IntrospectResponse{
          active: active,
          client_id: client_id,
          exp: exp,
          iat: iat,
          iss: iss,
          scope: scope,
          sub: sub,
          username: username
        }} ->
          assert active
          assert client_id
          assert exp
          assert iat
          assert iss
          assert scope
          assert sub
          assert username
        _ -> assert false
      end
    end
  end

  defp using_basic_auth(username, password) do
    authorization_header = "Basic " <> Base.encode64("#{username}:#{password}")
    %{req_headers: [{"authorization", authorization_header}]}
  end
end
