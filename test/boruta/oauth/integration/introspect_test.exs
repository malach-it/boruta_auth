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

  setup :verify_on_exit!

  describe "introspect request" do
    setup do
      client = insert(:client)
      resource_owner = %User{}

      token =
        insert(
          :token,
          type: "access_token",
          client: client,
          scope: "scope",
          sub: resource_owner.id
        )

      {:ok, client: client, token: token, resource_owner: resource_owner}
    end

    test "returns an error without body params" do
      assert Oauth.introspect(%Plug.Conn{body_params: %{}}, ApplicationMock) ==
               {:introspect_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request validation failed. Required properties client_id, token are missing at #.",
                  status: :bad_request
                }}
    end

    test "returns an error with invalid request" do
      assert Oauth.introspect(%Plug.Conn{body_params: %{}}, ApplicationMock) ==
               {:introspect_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request validation failed. Required properties client_id, token are missing at #.",
                  status: :bad_request
                }}
    end

    test "returns an error with invalid client_id" do
      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth("invalid_client_id", "bad_secret")

      assert Oauth.introspect(
               %Plug.Conn{
                 body_params: %{"token" => "token"},
                 req_headers: [{"authorization", authorization_header}, {"other", "header"}]
               },
               ApplicationMock
             ) ==
               {:introspect_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request validation failed. #/client_id do match required pattern /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.",
                  status: :bad_request
                }}
    end

    test "returns an error with invalid client_id/secret", %{client: client} do
      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client.id, "bad_secret")

      assert Oauth.introspect(
               %Plug.Conn{
                 body_params: %{"token" => "token"},
                 req_headers: [{"authorization", authorization_header}]
               },
               ApplicationMock
             ) ==
               {:introspect_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or client_secret.",
                  status: :unauthorized
                }}
    end

    test "returns an inactive token if token is inactive", %{client: client} do
      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client.id, client.secret)

      assert Oauth.introspect(
               %Plug.Conn{
                 body_params: %{"token" => "token"},
                 req_headers: [{"authorization", authorization_header}]
               },
               ApplicationMock
             ) ==
               {:introspect_success,
                %IntrospectResponse{
                  active: false,
                  client_id: nil,
                  exp: nil,
                  iat: nil,
                  iss: "boruta",
                  scope: nil,
                  sub: nil,
                  username: nil
                }}
    end

    test "returns a token introspected if token is active", %{
      client: client,
      token: token,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, fn _params ->
        {:ok, %ResourceOwner{sub: resource_owner.id, username: resource_owner.email}}
      end)

      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client.id, client.secret)

      case Oauth.introspect(
             %Plug.Conn{
               body_params: %{"token" => token.value},
               req_headers: [{"authorization", authorization_header}]
             },
             ApplicationMock
           ) do
        {:introspect_success,
         %IntrospectResponse{
           active: active,
           client_id: client_id,
           exp: exp,
           iat: iat,
           iss: iss,
           scope: scope,
           sub: sub,
           username: username,
           private_key: private_key
         }} ->
          assert active
          assert client_id == client.id
          assert private_key == client.private_key
          assert exp
          assert iat
          assert iss
          assert scope
          assert sub
          assert username
          assert iss == "boruta"

        _ ->
          assert false
      end
    end

    test "returns a token introspected if token is active (with body params)", %{
      client: client,
      token: token,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, fn _params ->
        {:ok, %ResourceOwner{sub: resource_owner.id, username: resource_owner.email}}
      end)

      case Oauth.introspect(
             %Plug.Conn{
               req_headers: [{"first", "header"}, {"second", "header"}],
               body_params: %{
                 "token" => token.value,
                 "client_id" => client.id,
                 "client_secret" => client.secret
               }
             },
             ApplicationMock
           ) do
        {:introspect_success,
         %IntrospectResponse{
           active: active,
           client_id: client_id,
           exp: exp,
           iat: iat,
           iss: iss,
           scope: scope,
           sub: sub,
           username: username,
           private_key: private_key
         }} ->
          assert active
          assert client_id == client.id
          assert private_key == client.private_key
          assert exp
          assert iat
          assert iss
          assert scope
          assert sub
          assert username
          assert iss == "boruta"

        _ ->
          assert false
      end
    end

    test "returns a token introspected with custom issuer", %{
      client: client,
      token: token,
      resource_owner: resource_owner
    } do
      issuer = "https://custom.issuer.com/"
      set_config_value([:issuer], issuer)

      ResourceOwners
      |> expect(:get_by, fn _params ->
        {:ok, %ResourceOwner{sub: resource_owner.id, username: resource_owner.email}}
      end)

      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client.id, client.secret)

      case Oauth.introspect(
             %Plug.Conn{
               body_params: %{"token" => token.value},
               req_headers: [{"authorization", authorization_header}]
             },
             ApplicationMock
           ) do
        {:introspect_success,
         %IntrospectResponse{
           iss: iss
         }} ->
          assert iss == issuer

          # remove the custom issuer config to prevent other tests from failing
          remove_config_value(:issuer)

        _ ->
          assert false
      end
    end
  end

  defp set_config_value(path, value) do
    :boruta
    |> Application.get_env(Boruta.Oauth)
    |> put_in(path, value)
    |> put_env()
  end

  defp remove_config_value(key) do
    :boruta
    |> Application.get_env(Boruta.Oauth)
    |> Keyword.delete(key)
    |> put_env()
  end

  defp put_env(value), do: Application.put_env(:boruta, Boruta.Oauth, value)

  defp using_basic_auth(username, password) do
    authorization_header = "Basic " <> Base.encode64("#{username}:#{password}")
    %{req_headers: [{"authorization", authorization_header}]}
  end
end
