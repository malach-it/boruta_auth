defmodule Boruta.OauthTest.PreauthorizeTest do
  use ExUnit.Case
  use Boruta.DataCase

  import Boruta.Factory
  import Mox

  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.AuthorizationSuccess
  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Support.ResourceOwners
  alias Boruta.Support.User

  setup :verify_on_exit!

  describe "preauthorize" do
    setup do
      user = %User{}

      resource_owner = %ResourceOwner{
        sub: user.id,
        username: user.email,
        authorization_details: []
      }

      client = insert(:client)

      wildcard_redirect_uri_client = insert(:client, redirect_uris: ["https://*.uri"])

      client_without_grant_type = insert(:client, supported_grant_types: [])

      client_with_scope =
        insert(:client,
          redirect_uris: ["https://redirect.uri"],
          authorize_scope: true,
          authorized_scopes: [insert(:scope, name: "scope"), insert(:scope, name: "other")]
        )

      {:ok,
       client: client,
       wildcard_redirect_uri_client: wildcard_redirect_uri_client,
       client_with_scope: client_with_scope,
       client_without_grant_type: client_without_grant_type,
       resource_owner: resource_owner}
    end

    test "returns an error if `response_type` is 'token' and schema is invalid" do
      assert Oauth.preauthorize(
               %Plug.Conn{query_params: %{"response_type" => "token"}},
               %ResourceOwner{sub: "sub"},
               ApplicationMock
             ) ==
               {:preauthorize_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Query params validation failed. Required properties client_id, redirect_uri are missing at #.",
                  status: :bad_request
                }}
    end

    test "returns an error if client_id is invalid" do
      assert Oauth.preauthorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "token",
                   "client_id" => "6a2f41a3-c54c-fce8-32d2-0324e1c32e22",
                   "redirect_uri" => "http://redirect.uri"
                 }
               },
               %ResourceOwner{sub: "sub"},
               ApplicationMock
             ) ==
               {:preauthorize_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or redirect_uri.",
                  status: :unauthorized,
                  format: nil,
                  redirect_uri: nil
                }}
    end

    test "returns an error if redirect_uri is invalid", %{client: client} do
      assert Oauth.preauthorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "token",
                   "client_id" => client.id,
                   "redirect_uri" => "http://bad.redirect.uri"
                 }
               },
               %ResourceOwner{sub: "sub"},
               ApplicationMock
             ) ==
               {:preauthorize_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or redirect_uri.",
                  status: :unauthorized,
                  format: nil,
                  redirect_uri: nil
                }}
    end

    test "returns an error if user is invalid", %{client: client} do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.preauthorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "token",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri
                 }
               },
               %ResourceOwner{sub: nil},
               ApplicationMock
             ) ==
               {:preauthorize_error,
                %Error{
                  error: :invalid_resource_owner,
                  error_description: "Resource owner is invalid.",
                  status: :unauthorized,
                  format: :fragment,
                  redirect_uri: redirect_uri
                }}
    end

    test "preauthorizes", %{client: client, resource_owner: resource_owner} do
      redirect_uri = List.first(client.redirect_uris)

      case Oauth.preauthorize(
             %Plug.Conn{
               query_params: %{
                 "response_type" => "token",
                 "client_id" => client.id,
                 "redirect_uri" => redirect_uri
               }
             },
             resource_owner,
             ApplicationMock
           ) do
        {:preauthorize_success,
         %AuthorizationSuccess{
           client: authorized_client,
           redirect_uri: authorized_redirect_uri,
           sub: authorized_sub
         }} ->
          assert authorized_client.id == client.id
          assert authorized_redirect_uri == redirect_uri
          assert authorized_sub == resource_owner.sub

        _ ->
          assert false
      end
    end

    test "preauthorizes with a wildcard client redirect uri", %{
      wildcard_redirect_uri_client: client,
      resource_owner: resource_owner
    } do
      redirect_uri = "https://wildcard-redirect-uri.uri"

      assert {:preauthorize_success,
              %AuthorizationSuccess{
                client: authorized_client,
                redirect_uri: authorized_redirect_uri,
                sub: authorized_sub
              }} =
               Oauth.preauthorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert authorized_client.id == client.id
      assert authorized_redirect_uri == redirect_uri
      assert authorized_sub == resource_owner.sub
    end

    test "preauthorizes if scope is authorized", %{
      client_with_scope: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      %{name: given_scope} = List.first(client.authorized_scopes)
      redirect_uri = List.first(client.redirect_uris)

      assert {:preauthorize_success,
              %AuthorizationSuccess{
                client: authorized_client,
                redirect_uri: authorized_redirect_uri,
                sub: authorized_sub
              }} =
               Oauth.preauthorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => given_scope
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert authorized_client.id == client.id
      assert authorized_redirect_uri == redirect_uri
      assert authorized_sub == resource_owner.sub
    end

    test "returns a token", %{client: client, resource_owner: resource_owner} do
      redirect_uri = List.first(client.redirect_uris)

      {:authorize_success,
       %AuthorizeResponse{
         access_token: access_token
       }} =
        Oauth.authorize(
          %Plug.Conn{
            query_params: %{
              "response_type" => "token",
              "client_id" => client.id,
              "redirect_uri" => redirect_uri
            }
          },
          resource_owner,
          ApplicationMock
        )

      assert access_token
    end

    test "returns an error if scope is unknown or unauthorized", %{
      client_with_scope: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      given_scope = "bad_scope"
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.preauthorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "token",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "scope" => given_scope
                 }
               },
               resource_owner,
               ApplicationMock
             ) ==
               {:preauthorize_error,
                %Error{
                  error: :invalid_scope,
                  error_description: "Given scopes are unknown or unauthorized.",
                  format: :fragment,
                  redirect_uri: "https://redirect.uri",
                  status: :bad_request
                }}
    end

    test "returns an error if grant type is not allowed by the client", %{
      client_without_grant_type: client,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.preauthorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "token",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "scope" => ""
                 }
               },
               resource_owner,
               ApplicationMock
             ) ==
               {:preauthorize_error,
                %Error{
                  error: :unsupported_grant_type,
                  error_description: "Client do not support given grant type.",
                  format: :fragment,
                  redirect_uri: redirect_uri,
                  status: :bad_request
                }}
    end
  end
end
