defmodule Boruta.OauthTest.HybridGrantTest do
  use ExUnit.Case
  use Boruta.DataCase

  import Boruta.Factory
  import Mox

  alias Boruta.Ecto
  alias Boruta.Ecto.ScopeStore
  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Scope
  alias Boruta.Repo
  alias Boruta.Support.ResourceOwners
  alias Boruta.Support.User

  setup :verify_on_exit!

  describe "hybrid grant - authorize" do
    setup do
      user = %User{}
      resource_owner = %ResourceOwner{sub: user.id, username: user.email}
      client = insert(:client, redirect_uris: ["https://redirect.uri"])
      wildcard_redirect_uri_client = insert(:client, redirect_uris: ["https://*.uri"])
      pkce_client = insert(:client, pkce: true, redirect_uris: ["https://redirect.uri"])
      client_without_grant_type = insert(:client, supported_grant_types: [])

      client_with_scope =
        insert(:client,
          redirect_uris: ["https://redirect.uri"],
          authorize_scope: true,
          authorized_scopes: [
            insert(:scope, name: "public", public: true),
            insert(:scope, name: "private", public: false)
          ]
        )

      {:ok,
       client: client,
       wildcard_redirect_uri_client: wildcard_redirect_uri_client,
       client_with_scope: client_with_scope,
       client_without_grant_type: client_without_grant_type,
       resource_owner: resource_owner,
       pkce_client: pkce_client}
    end

    test "returns an error if `response_type` is 'code' and schema is invalid" do
      assert Oauth.authorize(
               %Plug.Conn{query_params: %{"response_type" => "code token"}},
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

    test "returns an error if `response_mode` is invalid" do
      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code token",
                   "response_mode" => "invalid_response_mode",
                   "client_id" => "6a2f41a3-c54c-fce8-32d2-0324e1c32e22",
                   "redirect_uri" => "http://redirect.uri"
                 }
               },
               %ResourceOwner{sub: "sub"},
               ApplicationMock
             ) ==
               {:authorize_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Query params validation failed. #/response_mode do match required pattern /^(query|fragment)$/.",
                  status: :bad_request
                }}
    end

    test "returns an error if `client_id` is invalid" do
      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code token",
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
                  status: :unauthorized
                }}
    end

    test "returns an error if `redirect_uri` is invalid", %{client: client} do
      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code token",
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
                  status: :unauthorized
                }}
    end

    test "returns an error if user is invalid", %{client: client} do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code token",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri
                 }
               },
               %ResourceOwner{sub: nil},
               ApplicationMock
             ) ==
               {:authorize_error,
                %Error{
                  format: :fragment,
                  error: :invalid_resource_owner,
                  error_description: "Resource owner is invalid.",
                  status: :unauthorized,
                  redirect_uri: redirect_uri
                }}
    end

    test "returns an error if user is invalid (prompt=none)", %{client: client} do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code token",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "prompt" => "none"
                 }
               },
               %ResourceOwner{sub: nil},
               ApplicationMock
             ) ==
               {:authorize_error,
                %Error{
                  format: :fragment,
                  error: :login_required,
                  error_description: "User is not logged in.",
                  status: :unauthorized,
                  redirect_uri: redirect_uri
                }}
    end

    test "returns a code and a token without a nonce", %{
      client: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: code,
                access_token: access_token,
                expires_in: expires_in,
                token_type: "bearer"
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => "openid"
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :hybrid
      assert code
      assert access_token
      assert expires_in
    end

    test "creates a code and an id_token with a nonce", %{
      client: client,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)
      nonce = "nonce"

      Oauth.authorize(
        %Plug.Conn{
          query_params: %{
            "response_type" => "code id_token",
            "client_id" => client.id,
            "redirect_uri" => redirect_uri,
            "nonce" => nonce
          }
        },
        resource_owner,
        ApplicationMock
      )

      assert %Ecto.Token{nonce: ^nonce} = Repo.get_by(Ecto.Token, type: "code")
    end

    test "returns an error without a nonce", %{client: client, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code id_token",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "scope" => "openid"
                 }
               },
               resource_owner,
               ApplicationMock
             ) ==
               {:authorize_error,
                %Error{
                  format: :fragment,
                  error: :invalid_request,
                  error_description: "OpenID requests require a nonce.",
                  status: :bad_request,
                  redirect_uri: redirect_uri
                }}
    end

    test "returns an error as fragment without a nonce and `code id_token` response types", %{
      client: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code id_token",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "scope" => "openid"
                 }
               },
               resource_owner,
               ApplicationMock
             ) ==
               {:authorize_error,
                %Error{
                  format: :fragment,
                  error: :invalid_request,
                  error_description: "OpenID requests require a nonce.",
                  status: :bad_request,
                  redirect_uri: redirect_uri
                }}
    end

    test "returns an error as query params with `response_mode=query`, without a nonce, and `code id_token` response types",
         %{client: client, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code id_token",
                   "response_mode" => "query",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "scope" => "openid"
                 }
               },
               resource_owner,
               ApplicationMock
             ) ==
               {:authorize_error,
                %Error{
                  format: :query,
                  error: :invalid_request,
                  error_description: "OpenID requests require a nonce.",
                  status: :bad_request,
                  redirect_uri: redirect_uri
                }}
    end

    test "returns an error from Ecto", %{client: client, resource_owner: resource_owner} do
      resource_owner = %{resource_owner | sub: 1}

      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:authorize_error,
              %Boruta.Oauth.Error{
                error: :unknown_error,
                error_description:
                  "An error occurred during token creation: \"Could not create code : sub is invalid\".",
                format: :fragment,
                redirect_uri: "https://redirect.uri",
                state: nil,
                status: :internal_server_error
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => "openid"
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )
    end

    test "does not return an id_token without `openid` scope", %{
      client: client,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: code,
                id_token: id_token,
                expires_in: expires_in
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code id_token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :code
      assert code
      refute id_token
      assert expires_in
    end

    test "returns a code and an id_token", %{client: client, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)
      |> expect(:claims, fn (_sub, _scope) -> %{"email" => resource_owner.username} end)
      |> expect(:trust_chain, fn _client -> {:ok, []} end)

      redirect_uri = List.first(client.redirect_uris)
      nonce = "nonce"

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: code,
                id_token: id_token,
                expires_in: expires_in,
                token_type: nil
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code id_token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => "openid",
                     "nonce" => nonce
                   }
                 },
                 %{resource_owner | extra_claims: %{"resource_owner_extra_claim" => "claim"}},
                 ApplicationMock
               )

      assert type == :hybrid
      assert code
      assert id_token
      assert expires_in

      assert {:ok, claims} =
               Client.Crypto.verify_id_token_signature(
                 id_token,
                 JOSE.JWK.from_pem(client.public_key) |> JOSE.JWK.to_map()
               )

      client_id = client.id
      resource_owner_id = resource_owner.sub

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "sub" => ^resource_owner_id,
               "nonce" => ^nonce,
               "c_hash" => _c_hash,
               "resource_owner_extra_claim" => "claim"
             } = claims
    end

    test "returns a code and an id_token with `response_mode=query`", %{
      client: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)
      |> expect(:claims, fn (_sub, _scope) -> %{"email" => resource_owner.username} end)
      |> expect(:trust_chain, fn _client -> {:ok, []} end)

      redirect_uri = List.first(client.redirect_uris)
      nonce = "nonce"

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: code,
                id_token: id_token,
                expires_in: expires_in,
                token_type: nil,
                response_mode: "query"
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code id_token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => "openid",
                     "nonce" => nonce,
                     "response_mode" => "query"
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :hybrid
      assert code
      assert id_token
      assert expires_in

      assert {:ok, claims} =
               Client.Crypto.verify_id_token_signature(
                 id_token,
                 JOSE.JWK.from_pem(client.public_key) |> JOSE.JWK.to_map()
               )

      client_id = client.id
      resource_owner_id = resource_owner.sub

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "sub" => ^resource_owner_id,
               "nonce" => ^nonce,
               "c_hash" => _c_hash
             } = claims
    end

    test "returns a code and a token", %{client: client, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      redirect_uri = List.first(client.redirect_uris)
      nonce = "nonce"

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: code,
                access_token: access_token,
                expires_in: expires_in,
                token_type: "bearer"
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => "openid",
                     "nonce" => nonce
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :hybrid
      assert code
      assert access_token
      assert expires_in
    end

    test "returns a code and a token with `response_mode=query`", %{
      client: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      redirect_uri = List.first(client.redirect_uris)
      nonce = "nonce"

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: code,
                access_token: access_token,
                expires_in: expires_in,
                token_type: "bearer",
                response_mode: "query"
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => "openid",
                     "nonce" => nonce,
                     "response_mode" => "query"
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :hybrid
      assert code
      assert access_token
      assert expires_in
    end

    test "returns a code, a token and an id_token", %{
      resource_owner: resource_owner,
      client: client
    } do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)
      |> expect(:claims, fn (_sub, _scope) -> %{"email" => resource_owner.username} end)
      |> expect(:trust_chain, fn _client -> {:ok, []} end)

      redirect_uri = List.first(client.redirect_uris)
      nonce = "nonce"

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: code,
                id_token: id_token,
                access_token: access_token,
                expires_in: expires_in
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code id_token token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => "openid",
                     "nonce" => nonce
                   }
                 },
                 %{resource_owner | extra_claims: %{"resource_owner_extra_claim" => "claim"}},
                 ApplicationMock
               )

      assert type == :hybrid
      assert code
      assert id_token
      assert access_token
      assert expires_in

      assert {:ok, claims} =
               Client.Crypto.verify_id_token_signature(
                 id_token,
                 JOSE.JWK.from_pem(client.public_key) |> JOSE.JWK.to_map()
               )

      client_id = client.id
      resource_owner_id = resource_owner.sub

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "sub" => ^resource_owner_id,
               "nonce" => ^nonce,
               "c_hash" => _c_hash,
               "resource_owner_extra_claim" => "claim"
             } = claims
    end

    test "returns a code, a token and an id_token with `response_mode=query`", %{
      client: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)
      |> expect(:claims, fn (_sub, _scope) -> %{"email" => resource_owner.username} end)
      |> expect(:trust_chain, fn _client -> {:ok, []} end)

      redirect_uri = List.first(client.redirect_uris)
      nonce = "nonce"

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: code,
                id_token: id_token,
                access_token: access_token,
                expires_in: expires_in,
                response_mode: "query"
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code id_token token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => "openid",
                     "nonce" => nonce,
                     "response_mode" => "query"
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :hybrid
      assert code
      assert id_token
      assert access_token
      assert expires_in

      assert {:ok, claims} =
               Client.Crypto.verify_id_token_signature(
                 id_token,
                 JOSE.JWK.from_pem(client.public_key) |> JOSE.JWK.to_map()
               )

      client_id = client.id
      resource_owner_id = resource_owner.sub

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "sub" => ^resource_owner_id,
               "nonce" => ^nonce,
               "c_hash" => _c_hash
             } = claims
    end

    test "returns a code, a token and an id_token with a wildcard client redirect uri", %{
      wildcard_redirect_uri_client: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)
      |> expect(:claims, fn (_sub, _scope) -> %{"email" => resource_owner.username} end)
      |> expect(:trust_chain, fn _client -> {:ok, []} end)

      redirect_uri = "https://wildcard-redirect-uri.uri"
      nonce = "nonce"

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: code,
                id_token: id_token,
                access_token: access_token,
                expires_in: expires_in
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code id_token token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => "openid",
                     "nonce" => nonce
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :hybrid
      assert code
      assert id_token
      assert access_token
      assert expires_in

      assert {:ok, claims} =
               Client.Crypto.verify_id_token_signature(
                 id_token,
                 JOSE.JWK.from_pem(client.public_key) |> JOSE.JWK.to_map()
               )

      client_id = client.id
      resource_owner_id = resource_owner.sub

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "sub" => ^resource_owner_id,
               "nonce" => ^nonce,
               "c_hash" => _c_hash
             } = claims
    end

    test "returns a code with public scope", %{client: client, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      given_scope = "public"
      redirect_uri = List.first(client.redirect_uris)

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: value,
                expires_in: expires_in
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => given_scope
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :hybrid
      assert value
      assert expires_in
    end

    test "returns a code with public scope (from cache)", %{
      client: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      given_scope = "public"
      redirect_uri = List.first(client.redirect_uris)

      ScopeStore.put_public([%Scope{name: "public"}])

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: value,
                expires_in: expires_in
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => given_scope
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :hybrid
      assert value
      assert expires_in
    end

    test "returns an error with private scope", %{client: client, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      given_scope = "private"
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code token",
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
                  format: :fragment,
                  error: :invalid_scope,
                  error_description: "Given scopes are unknown or unauthorized.",
                  status: :bad_request,
                  redirect_uri: redirect_uri
                }}
    end

    test "returns a code if scope is authorized by client", %{
      client_with_scope: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      %{name: given_scope} = List.first(client.authorized_scopes)
      redirect_uri = List.first(client.redirect_uris)

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: value,
                expires_in: expires_in
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => given_scope
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :hybrid
      assert value
      assert expires_in
    end

    test "returns a code if scope is authorized by resource owner", %{
      client_with_scope: client,
      resource_owner: resource_owner
    } do
      given_scope = %Scope{name: "resource_owner:scope"}

      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [given_scope] end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: value,
                expires_in: expires_in
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "scope" => given_scope.name
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :hybrid
      assert value
      assert expires_in
    end

    test "returns an error if scope is unknown or unauthorized", %{
      client_with_scope: client,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      given_scope = "bad_scope"
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code token",
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
                  format: :fragment,
                  error: :invalid_scope,
                  error_description: "Given scopes are unknown or unauthorized.",
                  status: :bad_request,
                  redirect_uri: redirect_uri
                }}
    end

    test "returns an error if grant type is not allowed by client", %{
      client_without_grant_type: client,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code token",
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
                  format: :fragment,
                  error: :unsupported_grant_type,
                  error_description: "Client do not support given grant type.",
                  status: :bad_request,
                  redirect_uri: redirect_uri
                }}
    end

    test "returns a code with state", %{client: client, resource_owner: resource_owner} do
      given_state = "state"
      redirect_uri = List.first(client.redirect_uris)

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: value,
                expires_in: expires_in,
                state: state
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "state" => given_state
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :hybrid
      assert value
      assert expires_in
      assert state == given_state
    end

    test "returns an error with pkce client without code_challenge", %{
      pkce_client: client,
      resource_owner: resource_owner
    } do
      given_state = "state"
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code token",
                   "client_id" => client.id,
                   "redirect_uri" => redirect_uri,
                   "state" => given_state
                 }
               },
               resource_owner,
               ApplicationMock
             ) == {
               :authorize_error,
               %Boruta.Oauth.Error{
                 format: :fragment,
                 error: :invalid_request,
                 error_description: "Code challenge is invalid.",
                 status: :bad_request,
                 state: given_state,
                 redirect_uri: redirect_uri
               }
             }
    end

    test "returns a code with pkce client and code_challenge", %{
      pkce_client: client,
      resource_owner: resource_owner
    } do
      given_state = "state"
      given_code_challenge = "code challenge"
      given_code_challenge_method = "S256"
      redirect_uri = List.first(client.redirect_uris)

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: value,
                expires_in: expires_in,
                state: state,
                code_challenge: code_challenge,
                code_challenge_method: code_challenge_method
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "state" => given_state,
                     "code_challenge" => given_code_challenge,
                     "code_challenge_method" => given_code_challenge_method
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      %Ecto.Token{
        code_challenge: repo_code_challenge,
        code_challenge_method: repo_code_challenge_method,
        code_challenge_hash: repo_code_challenge_hash
      } = Repo.get_by(Ecto.Token, value: value)

      assert repo_code_challenge == nil
      assert repo_code_challenge_method == "S256"
      assert String.length(repo_code_challenge_hash) == 128

      assert type == :hybrid
      assert value
      assert expires_in
      assert state == given_state
      assert code_challenge == given_code_challenge
      assert code_challenge_method == given_code_challenge_method
    end

    test "code_challenge_method defaults to `plain`", %{
      pkce_client: client,
      resource_owner: resource_owner
    } do
      given_state = "state"
      given_code_challenge = "code challenge"
      redirect_uri = List.first(client.redirect_uris)

      assert {:authorize_success,
              %AuthorizeResponse{
                code: value
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "state" => given_state,
                     "code_challenge" => given_code_challenge
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      %Ecto.Token{
        code_challenge_method: repo_code_challenge_method
      } = Repo.get_by(Ecto.Token, value: value)

      assert repo_code_challenge_method == "plain"
    end
  end
end
