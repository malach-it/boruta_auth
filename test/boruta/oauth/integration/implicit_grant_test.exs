defmodule Boruta.OauthTest.ImplicitGrantTest do
  use ExUnit.Case
  use Boruta.DataCase

  import Boruta.Factory
  import Mox

  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.IdToken
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Support.ResourceOwners
  alias Boruta.Support.User

  describe "implicit grant" do
    setup do
      user = %User{}
      resource_owner = %ResourceOwner{sub: user.id, username: user.email}
      client = insert(:client, redirect_uris: ["https://redirect.uri"])
      client_without_grant_type = insert(:client, supported_grant_types: [])

      client_with_scope =
        insert(:client,
          redirect_uris: ["https://redirect.uri"],
          authorize_scope: true,
          authorized_scopes: [insert(:scope, name: "scope"), insert(:scope, name: "other")]
        )

      {:ok,
       client: client,
       client_with_scope: client_with_scope,
       client_without_grant_type: client_without_grant_type,
       resource_owner: resource_owner}
    end

    test "returns an error if `response_type` is 'token' and schema is invalid" do
      assert Oauth.authorize(
               %Plug.Conn{query_params: %{"response_type" => "token"}},
               %ResourceOwner{sub: "sub"},
               ApplicationMock
             ) ==
               {:authorize_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Query params validation failed. Required properties client_id, redirect_uri are missing at #.",
                  status: :bad_request
                }}
    end

    test "returns an error if client_id is invalid" do
      assert Oauth.authorize(
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
               {:authorize_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or redirect_uri.",
                  status: :unauthorized,
                  format: nil,
                  redirect_uri: nil
                }}
    end

    test "returns an error if redirect_uri is invalid", %{client: client} do
      assert Oauth.authorize(
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
               {:authorize_error,
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

      assert Oauth.authorize(
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
               {:authorize_error,
                %Error{
                  error: :invalid_resource_owner,
                  error_description: "Resource owner is invalid.",
                  status: :unauthorized,
                  format: :fragment,
                  redirect_uri: redirect_uri
                }}
    end

    test "returns an error from Ecto", %{client: client, resource_owner: resource_owner} do
      resource_owner = %{resource_owner | sub: 1}

      ResourceOwners
      |> expect(:get_by, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:authorize_error,
       %Boruta.Oauth.Error{
         error: :unknown_error,
         error_description: "\"Could not create access token : sub is invalid\"",
         format: :fragment,
         redirect_uri: "https://redirect.uri",
         state: nil,
         status: :internal_server_error
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
    end

    test "returns a token", %{client: client, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:get_by, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:authorize_success,
       %AuthorizeResponse{
         type: type,
         access_token: value,
         expires_in: expires_in,
         redirect_uri: ^redirect_uri
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

      assert type == :token
      assert value
      assert expires_in
    end

    test "does not return an id_token without `openid` scope", %{
      client: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:authorize_error,
              %Boruta.Oauth.Error{
                error: :invalid_request,
                error_description:
                  "Neither code, nor access_token, nor id_token could be created with given parameters.",
                format: :fragment,
                redirect_uri: "https://redirect.uri",
                status: :bad_request
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "id_token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )
    end

    test "returns an error with openid scope without nonce", %{
      client: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, fn _params -> {:ok, resource_owner} end)
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)
      |> expect(:claims, fn _sub, _scope -> %{} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {
               :authorize_error,
               %Boruta.Oauth.Error{
                 error: :invalid_request,
                 error_description: "OpenID requests require a nonce.",
                 format: :fragment,
                 redirect_uri: "https://redirect.uri",
                 status: :bad_request
               }
             } =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "id_token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => "openid"
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )
    end

    test "returns an id_token", %{client: client, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:get_by, fn _params -> {:ok, resource_owner} end)
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)
      |> expect(:claims, fn _sub, _scope -> %{} end)

      redirect_uri = List.first(client.redirect_uris)
      nonce = "nonce"
      state = "state"

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                id_token: value,
                redirect_uri: ^redirect_uri,
                state: ^state,
                token_type: nil
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "id_token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => "openid",
                     "nonce" => nonce,
                     "state" => state
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :token

      signer = Joken.Signer.create("RS512", %{"pem" => client.private_key, "aud" => client.id})

      {:ok, claims} = IdToken.Token.verify_and_validate(value, signer)
      client_id = client.id
      resource_owner_id = resource_owner.sub

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "sub" => ^resource_owner_id,
               "nonce" => ^nonce
             } = claims
    end

    test "does not return an id_token but a token without `openid` scope", %{
      client: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      {:authorize_success,
       %AuthorizeResponse{
         type: type,
         access_token: access_token,
         id_token: id_token,
         expires_in: expires_in
       }} =
        Oauth.authorize(
          %Plug.Conn{
            query_params: %{
              "response_type" => "id_token token",
              "client_id" => client.id,
              "redirect_uri" => redirect_uri
            }
          },
          resource_owner,
          ApplicationMock
        )

      assert type == :token
      assert access_token
      refute id_token
      assert expires_in
    end

    test "returns an id_token and a token with `openid` scope", %{
      client: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, fn _params -> {:ok, resource_owner} end)
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)
      |> expect(:claims, fn _sub, _scope -> %{} end)

      redirect_uri = List.first(client.redirect_uris)
      nonce = "nonce"

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                access_token: access_token,
                id_token: id_token,
                expires_in: expires_in,
                token_type: "bearer"
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "id_token token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => "openid",
                     "nonce" => nonce
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :token
      assert access_token
      assert id_token
      assert expires_in

      signer = Joken.Signer.create("RS512", %{"pem" => client.private_key, "aud" => client.id})
      {:ok, claims} = IdToken.Token.verify_and_validate(id_token, signer)
      client_id = client.id
      resource_owner_id = resource_owner.sub

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "at_hash" => _at_hash,
               "sub" => ^resource_owner_id,
               "nonce" => ^nonce
             } = claims
    end

    test "returns a token if scope is authorized", %{
      client_with_scope: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, fn _params -> {:ok, resource_owner} end)
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      %{name: given_scope} = List.first(client.authorized_scopes)
      redirect_uri = List.first(client.redirect_uris)

      case Oauth.authorize(
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
           ) do
        {:authorize_success,
         %AuthorizeResponse{
           type: type,
           access_token: value,
           expires_in: expires_in,
           token_type: "bearer"
         }} ->
          assert type == :token
          assert value
          assert expires_in

        _ ->
          assert false
      end
    end

    test "returns an error if scope is unknown or unauthorized", %{
      client_with_scope: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, fn _params -> resource_owner end)
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      given_scope = "bad_scope"
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
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
               {:authorize_error,
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
      ResourceOwners
      |> expect(:get_by, fn _params -> resource_owner end)
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
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
               {:authorize_error,
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
