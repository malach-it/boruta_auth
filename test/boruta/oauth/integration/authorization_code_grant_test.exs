defmodule Boruta.OauthTest.AuthorizationCodeGrantTest do
  use Boruta.DataCase

  import Boruta.Factory
  import Mox

  defmodule Token do
    @moduledoc false

    use Joken.Config, default_signer: :pem_rs512
  end

  alias Boruta.ClientsAdapter
  alias Boruta.Ecto
  alias Boruta.Ecto.ScopeStore
  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.PushedAuthorizationResponse
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.TokenResponse
  alias Boruta.Openid.SiopV2Response
  alias Boruta.Openid.VerifiablePresentationResponse
  alias Boruta.Repo
  alias Boruta.Support.ResourceOwners
  alias Boruta.Support.User

  setup :verify_on_exit!

  describe "authorization code grant - authorize" do
    setup do
      public_client = Ecto.Admin.get_client!(ClientsAdapter.public!().id)

      {:ok, _client} =
        Ecto.Admin.update_client(public_client, %{
          supported_grant_types: Oauth.Client.grant_types()
        })

      Ecto.ClientStore.invalidate_public()

      user = %User{}
      resource_owner = %ResourceOwner{sub: user.id, username: user.email}
      client = insert(:client, redirect_uris: ["https://redirect.uri"])

      confidential_client =
        insert(:client, redirect_uris: ["https://redirect.uri"], confidential: true)

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
       confidential_client: confidential_client,
       wildcard_redirect_uri_client: wildcard_redirect_uri_client,
       client_with_scope: client_with_scope,
       client_without_grant_type: client_without_grant_type,
       resource_owner: resource_owner,
       pkce_client: pkce_client}
    end

    test "returns an error if `response_type` is 'code' and schema is invalid" do
      assert Oauth.authorize(
               %Plug.Conn{query_params: %{"response_type" => "code"}},
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

    test "returns an error if `client_id` is invalid" do
      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code",
                   "client_id" => "invalid",
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

    test "returns an error if `redirect_uri` is invalid", %{client: client} do
      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code",
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
                   "response_type" => "code",
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
                  format: :query,
                  redirect_uri: redirect_uri
                }}
    end

    test "returns an error from Ecto", %{client: client, resource_owner: resource_owner} do
      resource_owner = %{resource_owner | sub: 1}

      redirect_uri = List.first(client.redirect_uris)

      assert {
               :authorize_error,
               %Boruta.Oauth.Error{
                 error: :unknown_error,
                 error_description: "\"Could not create code : sub is invalid\"",
                 format: :query,
                 redirect_uri: "https://redirect.uri",
                 state: nil,
                 status: :internal_server_error
               }
             } =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )
    end

    test "returns an error if user is invalid (prompt=none)", %{client: client} do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code",
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
                  format: :query,
                  error: :login_required,
                  error_description: "User is not logged in.",
                  status: :unauthorized,
                  redirect_uri: redirect_uri
                }}
    end

    test "returns an error when authorization details are invalid", %{
      client: client,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)
      authorization_details = %{}

      assert {
               :authorize_error,
               %Boruta.Oauth.Error{
                 error: :unknown_error,
                 error_description:
                   "\"authorization_details validation failed. The type at # `object` do not match the required types [\\\"array\\\"].\"",
                 format: :query,
                 redirect_uri: "https://redirect.uri",
                 state: nil,
                 status: :internal_server_error
               }
             } =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "authorization_details" => Jason.encode!(authorization_details)
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )
    end

    @tag :skip
    test "anonymous client tests"

    test "returns an error with anonymous clients (wallets)", %{resource_owner: resource_owner} do
      assert {:authorize_error,
              %Error{
                status: :bad_request,
                error: :invalid_request,
                error_description: "Invalid redirect_uri."
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code",
                     "client_id" => "did:key:test",
                     "redirect_uri" => "http://redirect.uri"
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )
    end

    test "returns a code", %{client: client, resource_owner: resource_owner} do
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
                     "response_type" => "code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :code
      assert value
      assert expires_in
    end

    test "returns a code with a confidential client", %{
      confidential_client: client,
      resource_owner: resource_owner
    } do
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
                     "response_type" => "code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :code
      assert value
      assert expires_in
    end

    test "returns a code with a wildcard client redirect uri", %{
      wildcard_redirect_uri_client: client,
      resource_owner: resource_owner
    } do
      redirect_uri = "https://wildcard-redirect-uri.uri"

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: value,
                expires_in: expires_in
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :code
      assert value
      assert expires_in
    end

    test "returns a code with a path wildcard (**) for long slugs" do
      client = insert(:client, redirect_uris: ["https://example.com/property/**"])
      user = %User{}
      resource_owner = %ResourceOwner{sub: user.id, username: user.email}

      # Test with a long slug exceeding 63 characters
      long_slug = "extra-mega-super-long-slug-exceeding-by-far-the-sixty-three-character-limit"
      redirect_uri = "https://example.com/property/#{long_slug}"

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: value,
                expires_in: expires_in
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :code
      assert value
      assert expires_in
    end

    test "nonce is stored in code", %{client: client, resource_owner: resource_owner} do
      redirect_uri = List.first(client.redirect_uris)
      nonce = "nonce"

      Oauth.authorize(
        %Plug.Conn{
          query_params: %{
            "response_type" => "code",
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

    test "returns a code with public scope", %{client: client, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      given_scope = "public"
      redirect_uri = List.first(client.redirect_uris)

      case Oauth.authorize(
             %Plug.Conn{
               query_params: %{
                 "response_type" => "code",
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
           code: value,
           expires_in: expires_in
         }} ->
          assert type == :code
          assert value
          assert expires_in

        _ ->
          assert false
      end
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

      case Oauth.authorize(
             %Plug.Conn{
               query_params: %{
                 "response_type" => "code",
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
           code: value,
           expires_in: expires_in
         }} ->
          assert type == :code
          assert value
          assert expires_in

        _ ->
          assert false
      end
    end

    test "returns an error with private scope", %{client: client, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      given_scope = "private"
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code",
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
                  status: :bad_request,
                  format: :query,
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

      case Oauth.authorize(
             %Plug.Conn{
               query_params: %{
                 "response_type" => "code",
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
           code: value,
           expires_in: expires_in
         }} ->
          assert type == :code
          assert value
          assert expires_in

        _ ->
          assert false
      end
    end

    test "returns a code if scope is authorized by resource owner", %{
      client_with_scope: client,
      resource_owner: resource_owner
    } do
      given_scope = %Scope{name: "resource_owner:scope"}

      ResourceOwners
      |> expect(:authorized_scopes, fn _resource_owner -> [given_scope] end)

      redirect_uri = List.first(client.redirect_uris)

      case Oauth.authorize(
             %Plug.Conn{
               query_params: %{
                 "response_type" => "code",
                 "client_id" => client.id,
                 "redirect_uri" => redirect_uri,
                 "scope" => given_scope.name
               }
             },
             resource_owner,
             ApplicationMock
           ) do
        {:authorize_success,
         %AuthorizeResponse{
           type: type,
           code: value,
           expires_in: expires_in
         }} ->
          assert type == :code
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
      |> expect(:authorized_scopes, fn _resource_owner -> [] end)

      given_scope = "bad_scope"
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "code",
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
                  format: :query,
                  redirect_uri: "https://redirect.uri",
                  status: :bad_request
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
                   "response_type" => "code",
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
                  format: :query,
                  redirect_uri: redirect_uri,
                  status: :bad_request
                }}
    end

    test "returns a code with state", %{client: client, resource_owner: resource_owner} do
      given_state = "state"
      redirect_uri = List.first(client.redirect_uris)

      case Oauth.authorize(
             %Plug.Conn{
               query_params: %{
                 "response_type" => "code",
                 "client_id" => client.id,
                 "redirect_uri" => redirect_uri,
                 "state" => given_state
               }
             },
             resource_owner,
             ApplicationMock
           ) do
        {:authorize_success,
         %AuthorizeResponse{
           type: type,
           code: value,
           expires_in: expires_in,
           state: state
         }} ->
          assert type == :code
          assert value
          assert expires_in
          assert state == given_state

        _ ->
          assert false
      end
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
                   "response_type" => "code",
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
                 error: :invalid_request,
                 error_description: "Code challenge is invalid.",
                 format: :query,
                 redirect_uri: "https://redirect.uri",
                 status: :bad_request,
                 state: given_state
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

      case Oauth.authorize(
             %Plug.Conn{
               query_params: %{
                 "response_type" => "code",
                 "client_id" => client.id,
                 "redirect_uri" => redirect_uri,
                 "state" => given_state,
                 "code_challenge" => given_code_challenge,
                 "code_challenge_method" => given_code_challenge_method
               }
             },
             resource_owner,
             ApplicationMock
           ) do
        {:authorize_success,
         %AuthorizeResponse{
           type: type,
           code: value,
           expires_in: expires_in,
           state: state,
           code_challenge: code_challenge,
           code_challenge_method: code_challenge_method
         }} ->
          %Ecto.Token{
            code_challenge: repo_code_challenge,
            code_challenge_method: repo_code_challenge_method,
            code_challenge_hash: repo_code_challenge_hash
          } = Repo.get_by(Ecto.Token, value: value)

          assert repo_code_challenge == nil
          assert repo_code_challenge_method == "S256"
          assert String.length(repo_code_challenge_hash) == 128

          assert type == :code
          assert value
          assert expires_in
          assert state == given_state
          assert code_challenge == given_code_challenge
          assert code_challenge_method == given_code_challenge_method

        _ ->
          assert false
      end
    end

    test "returns a code with pushed authorization request", %{
      client: client,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert {:request_stored,
              %PushedAuthorizationResponse{
                request_uri: request_uri
              }} =
               Oauth.pushed_authorization_request(
                 %Plug.Conn{
                   body_params: %{
                     "response_type" => "code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 ApplicationMock
               )

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: value,
                expires_in: expires_in
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "request_uri" => request_uri
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :code
      assert value
      assert expires_in
    end

    test "returns an error with expired pushed authorization request", %{
      client: client,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)
      Elixir.Ecto.Changeset.change(client, %{authorization_request_ttl: -1}) |> Repo.update()

      assert {:request_stored,
              %PushedAuthorizationResponse{
                request_uri: request_uri
              }} =
               Oauth.pushed_authorization_request(
                 %Plug.Conn{
                   body_params: %{
                     "response_type" => "code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 ApplicationMock
               )

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "request_uri" => request_uri
                 }
               },
               resource_owner,
               ApplicationMock
             ) ==
               {:authorize_error,
                %Boruta.Oauth.Error{
                  error: :invalid_request,
                  error_description: "Authorization request is expired.",
                  status: :bad_request
                }}
    end

    test "code_challenge_method defaults to `plain`", %{
      pkce_client: client,
      resource_owner: resource_owner
    } do
      given_state = "state"
      given_code_challenge = "code challenge"
      redirect_uri = List.first(client.redirect_uris)

      case Oauth.authorize(
             %Plug.Conn{
               query_params: %{
                 "response_type" => "code",
                 "client_id" => client.id,
                 "redirect_uri" => redirect_uri,
                 "state" => given_state,
                 "code_challenge" => given_code_challenge
               }
             },
             resource_owner,
             ApplicationMock
           ) do
        {:authorize_success,
         %AuthorizeResponse{
           code: value
         }} ->
          %Ecto.Token{
            code_challenge_method: repo_code_challenge_method,
            code_challenge_hash: repo_code_challenge_hash
          } = Repo.get_by(Ecto.Token, value: value)

          assert repo_code_challenge_method == "plain"
          assert repo_code_challenge_hash == Boruta.Oauth.Token.hash(given_code_challenge)

        _ ->
          assert false
      end
    end

    @tag :pkce_256
    test "code_challenge_method defaults to `S256`", %{
      pkce_client: client,
      resource_owner: resource_owner
    } do
      given_state = "state"
      given_code_challenge = :crypto.hash(:sha256, "challenge me") |> Base.url_encode64()
      given_code_challenge_method = "S256"
      redirect_uri = List.first(client.redirect_uris)

      case Oauth.authorize(
             %Plug.Conn{
               query_params: %{
                 "response_type" => "code",
                 "client_id" => client.id,
                 "redirect_uri" => redirect_uri,
                 "state" => given_state,
                 "code_challenge" => given_code_challenge,
                 "code_challenge_method" => given_code_challenge_method
               }
             },
             resource_owner,
             ApplicationMock
           ) do
        {:authorize_success,
         %AuthorizeResponse{
           code: value
         }} ->
          %Ecto.Token{
            code_challenge_method: repo_code_challenge_method,
            code_challenge_hash: repo_code_challenge_hash
          } = Repo.get_by(Ecto.Token, value: value)

          assert repo_code_challenge_method == "S256"
          assert repo_code_challenge_hash == Boruta.Oauth.Token.hash(given_code_challenge)

        _ ->
          assert false
      end
    end

    test "returns a code and stores authorization details", %{
      client: client,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      authorization_details = [
        %{
          "type" => "openid_credential",
          "format" => "jwt_vc"
        }
      ]

      assert {:authorize_success,
              %AuthorizeResponse{
                type: type,
                code: value,
                expires_in: expires_in
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "authorization_details" => Jason.encode!(authorization_details)
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert type == :code
      assert value
      assert expires_in

      assert Repo.get_by(Ecto.Token, value: value).authorization_details == authorization_details
    end

    test "returns an error with siopv2 when relying party redirect uri do not match (direct_post)" do
      redirect_uri = "openid:"

      assert {
               :authorize_error,
               %Error{
                 status: :bad_request,
                 error: :invalid_request,
                 error_description: "Invalid redirect_uri.",
                 format: :query,
                 redirect_uri: "openid:"
               }
             } =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code",
                     "client_id" => "did:key:test",
                     "redirect_uri" => redirect_uri,
                     "relying_party_redirect_uri" => "http://bad.uri",
                     "client_metadata" => "{}",
                     "nonce" => "nonce",
                     "scope" => "openid"
                   }
                 },
                 %ResourceOwner{sub: "did:key:test"},
                 ApplicationMock
               )
    end

    test "returns a code with siopv2 (direct_post - jwe)" do
      client_private_key = JOSE.JWK.generate_key({:ec, "P-256"})
      client_public_key = JOSE.JWK.to_public(client_private_key)
      redirect_uri = "openid:"

      assert {:authorize_success,
              %SiopV2Response{
                client: client,
                client_id: "did:key:test",
                response_type: "id_token",
                redirect_uri: ^redirect_uri,
                scope: "openid",
                issuer: issuer,
                response_mode: "direct_post",
                nonce: "nonce"
              } = response} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code",
                     "client_id" => "did:key:test",
                     "redirect_uri" => redirect_uri,
                     "client_metadata" => "{}",
                     "nonce" => "nonce",
                     "scope" => "openid",
                     "client_encryption_key" => client_public_key |> JOSE.JWK.to_map() |> elem(1),
                     "client_encryption_alg" => "ECDH-ES"
                   }
                 },
                 %ResourceOwner{sub: "did:key:test"},
                 ApplicationMock
               )

      assert issuer == Boruta.Config.issuer()
      assert client.public_client_id == Boruta.Config.issuer()

      assert SiopV2Response.redirect_to_deeplink(response, fn code -> code end) =~
               ~r"#{redirect_uri}"

      [_all, jwe] = Regex.run(~r/request=([^&]+)/, SiopV2Response.redirect_to_deeplink(response, fn code -> code end))

      assert %{
        "aud" => "did:key:test",
        "authorization_server_encryption_key" => %{},
        "client_id" => "boruta",
        "iss" => "boruta",
        "nonce" => "nonce",
        "response_mode" => "direct_post",
        "response_type" => "id_token",
        "scope" => "openid"
      } = JOSE.JWE.block_decrypt(client_private_key, jwe) |> elem(0) |> Jason.decode!()
    end

    test "returns a code with siopv2 (direct_post - jwt)" do
      redirect_uri = "openid:"

      assert {:authorize_success,
              %SiopV2Response{
                client: client,
                client_id: "did:key:test",
                response_type: "id_token",
                redirect_uri: ^redirect_uri,
                scope: "openid",
                issuer: issuer,
                response_mode: "direct_post",
                nonce: "nonce"
              } = response} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code",
                     "client_id" => "did:key:test",
                     "redirect_uri" => redirect_uri,
                     "client_metadata" => "{}",
                     "nonce" => "nonce",
                     "scope" => "openid"
                   }
                 },
                 %ResourceOwner{sub: "did:key:test"},
                 ApplicationMock
               )

      assert issuer == Boruta.Config.issuer()
      assert client.public_client_id == Boruta.Config.issuer()

      assert SiopV2Response.redirect_to_deeplink(response, fn code -> code end) =~
               ~r"#{redirect_uri}"

      [_all, jwt] = Regex.run(~r/request=([^&]+)/, SiopV2Response.redirect_to_deeplink(response, fn code -> code end))

      assert {:ok, %{
        "aud" => "did:key:test",
        "authorization_server_encryption_key" => %{},
        "client_id" => "boruta",
        "iss" => "boruta",
        "nonce" => "nonce",
        "response_mode" => "direct_post",
        "response_type" => "id_token",
        "scope" => "openid"
      }} = Oauth.Client.Crypto.verify_id_token_signature(
        jwt,
        JOSE.JWK.from_pem(client.private_key) |> JOSE.JWK.to_map()
      )
    end

    test "returns a code with siopv2 (post)" do
      redirect_uri = "openid://"
      relying_party_redirect_uri = "https://redirect.uri"
      client = insert(:client, response_mode: "post", redirect_uris: [redirect_uri, relying_party_redirect_uri])

      assert {:authorize_success,
              %SiopV2Response{
                client: response_client,
                client_id: client_id,
                response_type: "id_token",
                redirect_uri: ^redirect_uri,
                scope: "openid",
                issuer: issuer,
                response_mode: "post",
                nonce: "nonce"
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "relying_party_redirect_uri" => relying_party_redirect_uri,
                     "client_metadata" => "{}",
                     "nonce" => "nonce",
                     "scope" => "openid"
                   }
                 },
                 %ResourceOwner{sub: "sub"},
                 ApplicationMock
               )

      assert issuer == Boruta.Config.issuer()
      assert response_client.id == client.id
      assert client_id == client.id
    end

    test "returns an error with verifiable presentation when relying party redirect uri is invalid (direct_post)" do
      redirect_uri = "openid:"
      insert(:scope, name: "vp_token", public: true)

      resource_owner = %ResourceOwner{
        sub: "did:key:test",
        presentation_configuration: %{
          "vp_token" => %{
            definition: %{"test" => true}
          }
        }
      }

      assert {
               :authorize_error,
               %Error{
                 status: :bad_request,
                 error: :invalid_request,
                 error_description: "Invalid redirect_uri.",
                 format: :query,
                 redirect_uri: "openid:"
               }
             } =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "vp_token",
                     "client_id" => "did:key:test",
                     "relying_party_redirect_uri" => "http://bad.uri",
                     "redirect_uri" => redirect_uri,
                     "client_metadata" => "{}",
                     "nonce" => "nonce",
                     "scope" => "openid vp_token"
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )
    end

    @tag :skip
    test "returns a code with verifiable presentation and valid relying party redirect uri (direct_post)"

    test "returns a code with verifiable presentation (direct_post)" do
      redirect_uri = "openid:"
      insert(:scope, name: "vp_token", public: true)

      resource_owner = %ResourceOwner{
        sub: "did:key:test",
        presentation_configuration: %{
          "vp_token" => %{
            definition: %{"test" => true}
          }
        }
      }

      assert {:authorize_success,
              %VerifiablePresentationResponse{
                client: client,
                client_id: "did:key:test",
                response_type: "vp_token",
                redirect_uri: ^redirect_uri,
                scope: "openid vp_token",
                issuer: issuer,
                response_mode: "direct_post",
                nonce: "nonce",
                presentation_definition: %{"test" => true}
              } = response} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "vp_token",
                     "client_id" => "did:key:test",
                     "redirect_uri" => redirect_uri,
                     "client_metadata" => "{}",
                     "nonce" => "nonce",
                     "scope" => "openid vp_token"
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert issuer == Boruta.Config.issuer()
      assert client.public_client_id == Boruta.Config.issuer()

      assert VerifiablePresentationResponse.redirect_to_deeplink(response, fn code -> code end) =~
               ~r"#{redirect_uri}"
    end

    test "returns a code with verifiable presentation (post)" do
      redirect_uri = "openid://"
      client = insert(:client, response_mode: "post", redirect_uris: [redirect_uri])
      insert(:scope, name: "vp_token", public: true)

      resource_owner = %ResourceOwner{
        sub: "sub",
        presentation_configuration: %{
          "vp_token" => %{
            definition: %{"test" => true}
          }
        }
      }

      assert {:authorize_success,
              %VerifiablePresentationResponse{
                client: response_client,
                client_id: client_id,
                response_type: "vp_token",
                redirect_uri: ^redirect_uri,
                scope: "openid vp_token",
                issuer: issuer,
                response_mode: "post",
                nonce: "nonce",
                presentation_definition: %{"test" => true}
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "vp_token",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri,
                     "client_metadata" => "{}",
                     "nonce" => "nonce",
                     "scope" => "openid vp_token"
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert issuer == Boruta.Config.issuer()
      assert response_client.id == client.id
      assert client_id == client.id
    end

    @tag :skip
    test "returns an error without nonce with siopv2", %{client: client} do
      redirect_uri = List.first(client.redirect_uris)

      assert {
               :authorize_error,
               %Boruta.Oauth.Error{
                 error: :invalid_request,
                 error_description: "OpenID requests require a nonce.",
                 format: :query,
                 redirect_uri: "https://redirect.uri",
                 state: nil,
                 status: :bad_request
               }
             } =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "code",
                     "client_id" => "did:key:test",
                     "redirect_uri" => redirect_uri,
                     "client_metadata" => "{}"
                   }
                 },
                 %ResourceOwner{sub: "sub"},
                 ApplicationMock
               )
    end
  end

  describe "authorization code grant - token" do
    setup do
      user = %User{}
      resource_owner = %ResourceOwner{sub: user.id, username: user.email}
      client = insert(:client)
      confidential_client = insert(:client, confidential: true)
      pkce_client = insert(:client, pkce: true)
      client_without_grant_type = insert(:client, supported_grant_types: [])

      code =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris)
        )

      siopv2_code =
        insert(
          :token,
          type: "code",
          client: Repo.get_by(Ecto.Client, public_client_id: Boruta.Config.issuer()),
          sub: "did:key:test",
          redirect_uri: List.first(client.redirect_uris)
        )

      authorization_details_code =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          authorization_details: [%{"type" => "openid_credential", "format" => "jwt_vc"}]
        )

      confidential_code =
        insert(
          :token,
          type: "code",
          client: confidential_client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris)
        )

      openid_code =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          scope: "openid",
          nonce: "nonce"
        )

      pkce_code =
        insert(
          :token,
          type: "code",
          client: pkce_client,
          sub: resource_owner.sub,
          redirect_uri: List.first(pkce_client.redirect_uris),
          code_challenge: "code challenge",
          code_challenge_hash: Oauth.Token.hash("code challenge"),
          code_challenge_method: "plain"
        )

      expired_pkce_code =
        insert(
          :token,
          type: "code",
          client: pkce_client,
          sub: resource_owner.sub,
          redirect_uri: List.first(pkce_client.redirect_uris),
          code_challenge: "code challenge",
          code_challenge_hash: Oauth.Token.hash("code challenge"),
          code_challenge_method: "plain",
          expires_at: :os.system_time(:seconds) - 10
        )

      revoked_pkce_code =
        insert(
          :token,
          type: "code",
          client: pkce_client,
          sub: resource_owner.sub,
          redirect_uri: List.first(pkce_client.redirect_uris),
          code_challenge: "code challenge",
          code_challenge_hash: Oauth.Token.hash("code challenge"),
          code_challenge_method: "plain",
          revoked_at: DateTime.utc_now()
        )

      given_code_challenge =
        :crypto.hash(:sha256, "strong random challenge me from client")
        |> Base.url_encode64(padding: false)

      pkce_code_s256 =
        insert(
          :token,
          type: "code",
          client: pkce_client,
          sub: resource_owner.sub,
          redirect_uri: List.first(pkce_client.redirect_uris),
          code_challenge: given_code_challenge,
          code_challenge_hash: Oauth.Token.hash(given_code_challenge),
          code_challenge_method: "S256"
        )

      expired_code =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          expires_at: :os.system_time(:seconds) - 10
        )

      revoked_code =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          revoked_at: DateTime.utc_now()
        )

      bad_redirect_uri_code =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: "http://bad.redirect.uri"
        )

      code_with_scope =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          scope: "hello world"
        )

      {:ok,
       client: client,
       confidential_client: confidential_client,
       pkce_client: pkce_client,
       client_without_grant_type: client_without_grant_type,
       resource_owner: resource_owner,
       code: code,
       confidential_code: confidential_code,
       expired_code: expired_code,
       revoked_code: revoked_code,
       openid_code: openid_code,
       pkce_code: pkce_code,
       expired_pkce_code: expired_pkce_code,
       revoked_pkce_code: revoked_pkce_code,
       pkce_code_s256: pkce_code_s256,
       authorization_details_code: authorization_details_code,
       bad_redirect_uri_code: bad_redirect_uri_code,
       code_with_scope: code_with_scope,
       siopv2_code: siopv2_code}
    end

    test "returns an error if request is invalid" do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{"grant_type" => "authorization_code"}
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request body validation failed. Required properties code, client_id are missing at #.",
                  status: :bad_request
                }}
    end

    test "returns an error if `client_id` is invalid" do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "client_id" => "6a2f41a3-c54c-fce8-32d2-0324e1c32e22",
                   "code" => "bad_code",
                   "redirect_uri" => "http://redirect.uri"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or redirect_uri.",
                  status: :unauthorized
                }}
    end

    test "returns an error if `client_id` is absent" do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "code" => "bad_code",
                   "redirect_uri" => "http://redirect.uri"
                 }
               },
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

    test "returns an error if `code` is invalid", %{client: client} do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "client_id" => client.id,
                   "code" => "bad_code",
                   "redirect_uri" => redirect_uri
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns an error if `code` and request redirect_uri do not match", %{
      client: client,
      bad_redirect_uri_code: bad_redirect_uri_code
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "client_id" => client.id,
                   "code" => bad_redirect_uri_code.value,
                   "redirect_uri" => redirect_uri
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns an error if grant type is not allowed by client", %{
      client_without_grant_type: client,
      code: code
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri
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

    test "returns an error when code is expired", %{
      client: client,
      expired_code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 1, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns an error when code is revoked", %{
      client: client,
      revoked_code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 1, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns an error if code was issued to an other client", %{
      code: code,
      resource_owner: resource_owner
    } do
      client = insert(:client)

      ResourceOwners
      |> expect(:get_by, 1, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns an error when client secret is invalid and client confidential", %{
      confidential_client: client,
      confidential_code: code
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "client_id" => client.id,
                   "client_secret" => "bad_secret",
                   "code" => code.value,
                   "redirect_uri" => redirect_uri
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or redirect_uri.",
                  status: :unauthorized
                }}
    end

    # TODO test dpop implementation

    test "returns a token when dpop is valid", %{
      client: client,
      code: code,
      resource_owner: resource_owner
    } do
      {_, jwk} = JOSE.JWK.from_pem(valid_public_key()) |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS512", %{"pem" => valid_private_key()}, %{
          "jwk" => jwk,
          "typ" => "dpop+jwt"
        })

      {:ok, dpop, _claims} =
        Token.encode_and_sign(
          %{
            "htu" => "http://host/pa/th",
            "htm" => "POST"
          },
          signer
        )

      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      case Oauth.token(
             %Plug.Conn{
               method: "POST",
               host: "host",
               request_path: "/pa/th",
               req_headers: [{"dpop", dpop}],
               body_params: %{
                 "grant_type" => "authorization_code",
                 "client_id" => client.id,
                 "code" => code.value,
                 "redirect_uri" => redirect_uri
               }
             },
             ApplicationMock
           ) do
        {:token_success,
         %TokenResponse{
           token_type: token_type,
           access_token: access_token,
           expires_in: expires_in,
           refresh_token: refresh_token
         }} ->
          assert token_type == "bearer"
          assert access_token
          assert expires_in
          assert refresh_token

        _ ->
          assert false
      end
    end

    test "returns a token", %{client: client, code: code, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

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
                     "grant_type" => "authorization_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert access_token
      assert expires_in
      assert refresh_token
      refute Repo.get_by(Ecto.Token, value: access_token).revoked_at
    end

    test "stores previous code", %{client: client, code: code, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:token_success,
              %TokenResponse{
                access_token: access_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "authorization_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 ApplicationMock
               )

      assert token = Repo.get_by(Ecto.Token, value: access_token)
      assert token.previous_code == code.value
    end

    test "returns a token with a confidential client", %{
      confidential_client: client,
      confidential_code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      case Oauth.token(
             %Plug.Conn{
               body_params: %{
                 "grant_type" => "authorization_code",
                 "client_id" => client.id,
                 "client_secret" => client.secret,
                 "code" => code.value,
                 "redirect_uri" => redirect_uri
               }
             },
             ApplicationMock
           ) do
        {:token_success,
         %TokenResponse{
           token_type: token_type,
           access_token: access_token,
           expires_in: expires_in,
           refresh_token: refresh_token
         }} ->
          assert token_type == "bearer"
          assert access_token
          assert expires_in
          assert refresh_token

        _ ->
          assert false
      end
    end

    test "returns an error if token is used twice", %{
      client: client,
      code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 3, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:token_success, %TokenResponse{access_token: access_token}} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "authorization_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 ApplicationMock
               )

      assert {:token_error,
              %Error{
                error: :invalid_grant,
                error_description: "Given authorization code is invalid, revoked, or expired.",
                status: :bad_request
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "authorization_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 ApplicationMock
               )

      assert Repo.get_by(Ecto.Token, value: access_token).revoked_at
    end

    test "returns a token and an id_token with openid scope", %{
      client: client,
      openid_code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params ->
        {:ok,
         %{
           resource_owner
           | extra_claims: %{
               "term" => true,
               "hide" => %{"display" => false, "hide" => true},
               "hide_value" => %{"display" => false, "hide" => true},
               "value" => %{"value" => true},
               "display" => %{"value" => true, "display" => []},
               "status" => %{"value" => true, "display" => ["status"], "status" => "suspended"}
             }
         }}
      end)
      |> expect(:claims, fn _sub, _scope -> %{} end)

      redirect_uri = List.first(client.redirect_uris)

      case Oauth.token(
             %Plug.Conn{
               body_params: %{
                 "grant_type" => "authorization_code",
                 "client_id" => client.id,
                 "code" => code.value,
                 "redirect_uri" => redirect_uri
               }
             },
             ApplicationMock
           ) do
        {:token_success,
         %TokenResponse{
           token_type: token_type,
           access_token: access_token,
           id_token: id_token,
           expires_in: expires_in,
           refresh_token: refresh_token
         }} ->
          assert token_type == "bearer"
          assert access_token
          assert id_token
          assert expires_in
          assert refresh_token

          signer =
            Joken.Signer.create("RS512", %{"pem" => client.private_key, "aud" => client.id})

          {:ok, claims} = Oauth.Client.Token.verify_and_validate(id_token, signer)
          client_id = client.id
          resource_owner_id = resource_owner.sub
          nonce = code.nonce

          assert %{
                   "aud" => ^client_id,
                   "iat" => _iat,
                   "exp" => _exp,
                   "sub" => ^resource_owner_id,
                   "nonce" => ^nonce,
                   "display" => true,
                   "status" => %{"status" => "suspended", "value" => true},
                   "term" => true,
                   "value" => true
                 } = claims

        _ ->
          assert false
      end
    end

    test "returns a token from cache", %{
      client: client,
      code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)
      Ecto.Codes.get_by(value: code.value, redirect_uri: redirect_uri)

      case Oauth.token(
             %Plug.Conn{
               body_params: %{
                 "grant_type" => "authorization_code",
                 "client_id" => client.id,
                 "code" => code.value,
                 "redirect_uri" => redirect_uri
               }
             },
             ApplicationMock
           ) do
        {:token_success,
         %TokenResponse{
           token_type: token_type,
           access_token: access_token,
           expires_in: expires_in,
           refresh_token: refresh_token
         }} ->
          assert token_type == "bearer"
          assert access_token
          assert expires_in
          assert refresh_token

        _ ->
          assert false
      end
    end

    test "returns a token with scope", %{
      client: client,
      code_with_scope: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      case Oauth.token(
             %Plug.Conn{
               body_params: %{
                 "grant_type" => "authorization_code",
                 "client_id" => client.id,
                 "code" => code.value,
                 "redirect_uri" => redirect_uri
               }
             },
             ApplicationMock
           ) do
        {:token_success,
         %TokenResponse{
           token_type: token_type,
           access_token: access_token,
           expires_in: expires_in,
           refresh_token: refresh_token
         }} ->
          assert token_type == "bearer"
          assert access_token
          assert expires_in
          assert refresh_token

        _ ->
          assert false
      end
    end

    test "returns an error with pkce without code_verifier", %{
      pkce_client: client,
      pkce_code: code
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description: "PKCE request invalid.",
                  status: :bad_request
                }}
    end

    test "returns an error with pkce and bad code_verifier", %{
      pkce_client: client,
      pkce_code: code,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      ResourceOwners
      |> expect(:get_by, fn _params -> {:ok, resource_owner} end)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri,
                   "code_verifier" => "bad code verifier"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description: "Code verifier is invalid.",
                  status: :bad_request
                }}
    end

    test "returns an error when code is expired with pkce", %{
      pkce_client: client,
      expired_pkce_code: code,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      ResourceOwners
      |> expect(:get_by, 1, fn _params -> {:ok, resource_owner} end)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri,
                   "code_verifier" => code.code_challenge
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns an error when code is revoked with pkce", %{
      pkce_client: client,
      revoked_pkce_code: code,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      ResourceOwners
      |> expect(:get_by, 1, fn _params -> {:ok, resource_owner} end)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "authorization_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri,
                   "code_verifier" => code.code_challenge
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns a token with pkce (plain code challenge)", %{
      pkce_client: client,
      pkce_code: code,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      case Oauth.token(
             %Plug.Conn{
               body_params: %{
                 "grant_type" => "authorization_code",
                 "client_id" => client.id,
                 "code" => code.value,
                 "redirect_uri" => redirect_uri,
                 "code_verifier" => code.code_challenge
               }
             },
             ApplicationMock
           ) do
        {:token_success,
         %TokenResponse{
           token_type: token_type,
           access_token: access_token,
           expires_in: expires_in,
           refresh_token: refresh_token
         }} ->
          assert token_type == "bearer"
          assert access_token
          assert expires_in
          assert refresh_token

        _ ->
          assert false
      end
    end

    @tag :pkce_256
    test "returns a token with pkce `S256`", %{
      pkce_client: client,
      pkce_code_s256: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      case Oauth.token(
             %Plug.Conn{
               body_params: %{
                 "grant_type" => "authorization_code",
                 "client_id" => client.id,
                 "code" => code.value,
                 "redirect_uri" => redirect_uri,
                 "code_verifier" => "strong random challenge me from client"
               }
             },
             ApplicationMock
           ) do
        {:token_success,
         %TokenResponse{
           token_type: token_type,
           access_token: access_token,
           expires_in: expires_in,
           refresh_token: refresh_token
         }} ->
          assert token_type == "bearer"
          assert access_token
          assert expires_in
          assert refresh_token

        _ ->
          assert false
      end
    end

    test "returns a token with authorization details", %{
      client: client,
      authorization_details_code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

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
                     "grant_type" => "authorization_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert access_token
      assert expires_in
      assert refresh_token

      assert Repo.get_by(Ecto.Token, value: access_token).authorization_details ==
               code.authorization_details
    end

    test "returns a token with siopv2", %{siopv2_code: code} do
      assert {:token_success,
              %TokenResponse{
                token_type: _token_type,
                access_token: _access_token,
                expires_in: _expires_in,
                refresh_token: _refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "authorization_code",
                     "client_id" => "did:key:test",
                     "code" => code.value,
                     "client_metadata" => "{}"
                   }
                 },
                 ApplicationMock
               )
    end
  end

  describe "agent code grant - token" do
    setup do
      user = %User{}
      resource_owner = %ResourceOwner{sub: user.id, username: user.email}
      client = insert(:client)
      confidential_client = insert(:client, confidential: true)
      pkce_client = insert(:client, pkce: true)
      client_without_grant_type = insert(:client, supported_grant_types: [])

      code =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris)
        )

      siopv2_code =
        insert(
          :token,
          type: "code",
          client: Repo.get_by(Ecto.Client, public_client_id: Boruta.Config.issuer()),
          sub: "did:key:test",
          redirect_uri: List.first(client.redirect_uris)
        )

      authorization_details_code =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          authorization_details: [%{"type" => "openid_credential", "format" => "jwt_vc"}]
        )

      confidential_code =
        insert(
          :token,
          type: "code",
          client: confidential_client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris)
        )

      openid_code =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          scope: "openid",
          nonce: "nonce"
        )

      pkce_code =
        insert(
          :token,
          type: "code",
          client: pkce_client,
          sub: resource_owner.sub,
          redirect_uri: List.first(pkce_client.redirect_uris),
          code_challenge: "code challenge",
          code_challenge_hash: Oauth.Token.hash("code challenge"),
          code_challenge_method: "plain"
        )

      expired_pkce_code =
        insert(
          :token,
          type: "code",
          client: pkce_client,
          sub: resource_owner.sub,
          redirect_uri: List.first(pkce_client.redirect_uris),
          code_challenge: "code challenge",
          code_challenge_hash: Oauth.Token.hash("code challenge"),
          code_challenge_method: "plain",
          expires_at: :os.system_time(:seconds) - 10
        )

      revoked_pkce_code =
        insert(
          :token,
          type: "code",
          client: pkce_client,
          sub: resource_owner.sub,
          redirect_uri: List.first(pkce_client.redirect_uris),
          code_challenge: "code challenge",
          code_challenge_hash: Oauth.Token.hash("code challenge"),
          code_challenge_method: "plain",
          revoked_at: DateTime.utc_now()
        )

      given_code_challenge =
        :crypto.hash(:sha256, "strong random challenge me from client")
        |> Base.url_encode64(padding: false)

      pkce_code_s256 =
        insert(
          :token,
          type: "code",
          client: pkce_client,
          sub: resource_owner.sub,
          redirect_uri: List.first(pkce_client.redirect_uris),
          code_challenge: given_code_challenge,
          code_challenge_hash: Oauth.Token.hash(given_code_challenge),
          code_challenge_method: "S256"
        )

      expired_code =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          expires_at: :os.system_time(:seconds) - 10
        )

      revoked_code =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          revoked_at: DateTime.utc_now()
        )

      bad_redirect_uri_code =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: "http://bad.redirect.uri"
        )

      code_with_scope =
        insert(
          :token,
          type: "code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          scope: "hello world"
        )

      {:ok,
       client: client,
       confidential_client: confidential_client,
       pkce_client: pkce_client,
       client_without_grant_type: client_without_grant_type,
       resource_owner: resource_owner,
       code: code,
       confidential_code: confidential_code,
       expired_code: expired_code,
       revoked_code: revoked_code,
       openid_code: openid_code,
       pkce_code: pkce_code,
       expired_pkce_code: expired_pkce_code,
       revoked_pkce_code: revoked_pkce_code,
       pkce_code_s256: pkce_code_s256,
       authorization_details_code: authorization_details_code,
       bad_redirect_uri_code: bad_redirect_uri_code,
       code_with_scope: code_with_scope,
       siopv2_code: siopv2_code}
    end

    test "returns an error if request is invalid" do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{"grant_type" => "agent_code"}
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request body validation failed. Required properties code, client_id, bind_data, bind_configuration are missing at #.",
                  status: :bad_request
                }}
    end

    test "returns an error if `client_id` is invalid" do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "client_id" => "6a2f41a3-c54c-fce8-32d2-0324e1c32e22",
                   "code" => "bad_code",
                   "redirect_uri" => "http://redirect.uri",
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or redirect_uri.",
                  status: :unauthorized
                }}
    end

    test "returns an error if `client_id` is absent" do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "code" => "bad_code",
                   "redirect_uri" => "http://redirect.uri",
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
                 }
               },
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

    test "returns an error if `code` is invalid", %{client: client} do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "client_id" => client.id,
                   "code" => "bad_code",
                   "redirect_uri" => redirect_uri,
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns an error if `code` and request redirect_uri do not match", %{
      client: client,
      bad_redirect_uri_code: bad_redirect_uri_code
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "client_id" => client.id,
                   "code" => bad_redirect_uri_code.value,
                   "redirect_uri" => redirect_uri,
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns an error if grant type is not allowed by client", %{
      client_without_grant_type: client,
      code: code
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri,
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
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

    test "returns an error when code is expired", %{
      client: client,
      expired_code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 1, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri,
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns an error when code is revoked", %{
      client: client,
      revoked_code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 1, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri,
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns an error if code was issued to an other client", %{
      code: code,
      resource_owner: resource_owner
    } do
      client = insert(:client)

      ResourceOwners
      |> expect(:get_by, 1, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri,
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns an error when client secret is invalid and client confidential", %{
      confidential_client: client,
      confidential_code: code
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "client_id" => client.id,
                   "client_secret" => "bad_secret",
                   "code" => code.value,
                   "redirect_uri" => redirect_uri,
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_client,
                  error_description: "Invalid client_id or redirect_uri.",
                  status: :unauthorized
                }}
    end

    # TODO test dpop implementation

    test "returns a token when dpop is valid", %{
      client: client,
      code: code,
      resource_owner: resource_owner
    } do
      {_, jwk} = JOSE.JWK.from_pem(valid_public_key()) |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS512", %{"pem" => valid_private_key()}, %{
          "jwk" => jwk,
          "typ" => "dpop+jwt"
        })

      {:ok, dpop, _claims} =
        Token.encode_and_sign(
          %{
            "htu" => "http://host/pa/th",
            "htm" => "POST"
          },
          signer
        )

      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                agent_token: agent_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   method: "POST",
                   host: "host",
                   request_path: "/pa/th",
                   req_headers: [{"dpop", dpop}],
                   body_params: %{
                     "grant_type" => "agent_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert agent_token
      assert expires_in
      assert refresh_token
    end

    test "returns a token", %{client: client, code: code, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                agent_token: agent_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert agent_token
      assert expires_in
      assert refresh_token
      refute Repo.get_by(Ecto.Token, value: agent_token).revoked_at
    end

    test "returns a token with bind data", %{
      client: client,
      code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                agent_token: agent_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri,
                     "bind_data" => Jason.encode!(%{"test" => true}),
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert agent_token
      assert expires_in
      assert refresh_token
      refute Repo.get_by(Ecto.Token, value: agent_token).revoked_at
      assert Repo.get_by(Ecto.Token, value: agent_token).bind_data == %{"test" => true}
    end

    test "stores previous code", %{client: client, code: code, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:token_success,
              %TokenResponse{
                agent_token: agent_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token = Repo.get_by(Ecto.Token, value: agent_token)
      assert token.previous_code == code.value
    end

    test "returns a token with a confidential client", %{
      confidential_client: client,
      confidential_code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      case Oauth.token(
             %Plug.Conn{
               body_params: %{
                 "grant_type" => "agent_code",
                 "client_id" => client.id,
                 "client_secret" => client.secret,
                 "code" => code.value,
                 "redirect_uri" => redirect_uri,
                 "bind_data" => "{}",
                 "bind_configuration" => "{}"
               }
             },
             ApplicationMock
           ) do
        {:token_success,
         %TokenResponse{
           token_type: token_type,
           agent_token: agent_token,
           expires_in: expires_in,
           refresh_token: refresh_token
         }} ->
          assert token_type == "bearer"
          assert agent_token
          assert expires_in
          assert refresh_token

        _ ->
          assert false
      end
    end

    test "returns an error if token is used twice", %{
      client: client,
      code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 3, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:token_success, %TokenResponse{agent_token: agent_token}} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert {:token_error,
              %Error{
                error: :invalid_grant,
                error_description: "Given authorization code is invalid, revoked, or expired.",
                status: :bad_request
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert Repo.get_by(Ecto.Token, value: agent_token).revoked_at
    end

    test "returns a token and an id_token with openid scope", %{
      client: client,
      openid_code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params ->
        {:ok,
         %{
           resource_owner
           | extra_claims: %{
               "term" => true,
               "hide" => %{"display" => false, "hide" => true},
               "hide_value" => %{"display" => false, "hide" => true},
               "value" => %{"value" => true},
               "display" => %{"value" => true, "display" => []},
               "status" => %{"value" => true, "display" => ["status"], "status" => "suspended"}
             }
         }}
      end)
      |> expect(:claims, fn _sub, _scope -> %{} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                agent_token: agent_token,
                id_token: id_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert agent_token
      assert id_token
      assert expires_in
      assert refresh_token

      signer = Joken.Signer.create("RS512", %{"pem" => client.private_key, "aud" => client.id})

      {:ok, claims} = Oauth.Client.Token.verify_and_validate(id_token, signer)
      client_id = client.id
      resource_owner_id = resource_owner.sub
      nonce = code.nonce

      assert %{
               "aud" => ^client_id,
               "iat" => _iat,
               "exp" => _exp,
               "sub" => ^resource_owner_id,
               "nonce" => ^nonce,
               "display" => true,
               "status" => %{"status" => "suspended", "value" => true},
               "term" => true,
               "value" => true
             } = claims
    end

    test "returns a token from cache", %{
      client: client,
      code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)
      Ecto.Codes.get_by(value: code.value, redirect_uri: redirect_uri)

      case Oauth.token(
             %Plug.Conn{
               body_params: %{
                 "grant_type" => "agent_code",
                 "client_id" => client.id,
                 "code" => code.value,
                 "redirect_uri" => redirect_uri,
                 "bind_data" => "{}",
                 "bind_configuration" => "{}"
               }
             },
             ApplicationMock
           ) do
        {:token_success,
         %TokenResponse{
           token_type: token_type,
           agent_token: agent_token,
           expires_in: expires_in,
           refresh_token: refresh_token
         }} ->
          assert token_type == "bearer"
          assert agent_token
          assert expires_in
          assert refresh_token

        _ ->
          assert false
      end
    end

    test "returns a token with scope", %{
      client: client,
      code_with_scope: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      case Oauth.token(
             %Plug.Conn{
               body_params: %{
                 "grant_type" => "agent_code",
                 "client_id" => client.id,
                 "code" => code.value,
                 "redirect_uri" => redirect_uri,
                 "bind_data" => "{}",
                 "bind_configuration" => "{}"
               }
             },
             ApplicationMock
           ) do
        {:token_success,
         %TokenResponse{
           token_type: token_type,
           agent_token: agent_token,
           expires_in: expires_in,
           refresh_token: refresh_token
         }} ->
          assert token_type == "bearer"
          assert agent_token
          assert expires_in
          assert refresh_token

        _ ->
          assert false
      end
    end

    test "returns an error with pkce without code_verifier", %{
      pkce_client: client,
      pkce_code: code
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri,
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description: "PKCE request invalid.",
                  status: :bad_request
                }}
    end

    test "returns an error with pkce and bad code_verifier", %{
      pkce_client: client,
      pkce_code: code,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      ResourceOwners
      |> expect(:get_by, fn _params -> {:ok, resource_owner} end)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri,
                   "code_verifier" => "bad code challenge",
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description: "Code verifier is invalid.",
                  status: :bad_request
                }}
    end

    test "returns an error when code is expired with pkce", %{
      pkce_client: client,
      expired_pkce_code: code,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      ResourceOwners
      |> expect(:get_by, 1, fn _params -> {:ok, resource_owner} end)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri,
                   "code_verifier" => code.code_challenge,
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns an error when code is revoked with pkce", %{
      pkce_client: client,
      revoked_pkce_code: code,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      ResourceOwners
      |> expect(:get_by, 1, fn _params -> {:ok, resource_owner} end)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "agent_code",
                   "client_id" => client.id,
                   "code" => code.value,
                   "redirect_uri" => redirect_uri,
                   "code_verifier" => code.code_challenge,
                   "bind_data" => "{}",
                   "bind_configuration" => "{}"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_grant,
                  error_description: "Given authorization code is invalid, revoked, or expired.",
                  status: :bad_request
                }}
    end

    test "returns a token with pkce", %{
      pkce_client: client,
      pkce_code: code,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                agent_token: agent_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri,
                     "code_verifier" => code.code_challenge,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert agent_token
      assert expires_in
      assert refresh_token
    end

    @tag :pkce_256
    test "returns a token with pkce `S256`", %{
      pkce_client: client,
      pkce_code_s256: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                agent_token: agent_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri,
                     "code_verifier" => "strong random challenge me from client",
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert agent_token
      assert expires_in
      assert refresh_token
    end

    test "returns a token with authorization details", %{
      client: client,
      authorization_details_code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      redirect_uri = List.first(client.redirect_uris)

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                agent_token: agent_token,
                expires_in: expires_in,
                refresh_token: refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_code",
                     "client_id" => client.id,
                     "code" => code.value,
                     "redirect_uri" => redirect_uri,
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert agent_token
      assert expires_in
      assert refresh_token

      assert Repo.get_by(Ecto.Token, value: agent_token).authorization_details ==
               code.authorization_details
    end

    @tag :skip
    test "returns a token with siopv2", %{siopv2_code: code} do
      assert {:token_success,
              %TokenResponse{
                token_type: _token_type,
                agent_token: _agent_token,
                expires_in: _expires_in,
                refresh_token: _refresh_token
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "agent_code",
                     "client_id" => "did:key:test",
                     "code" => code.value,
                     "client_metadata" => "{}",
                     "bind_data" => "{}",
                     "bind_configuration" => "{}"
                   }
                 },
                 ApplicationMock
               )
    end
  end

  def valid_public_key do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def valid_private_key do
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVO\nf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa\n9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8Wd\nSq3dGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/\nU8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2t\npyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQABAoIBAG0dg/upL8k1IWiv\n8BNphrXIYLYQmiiBQTPJWZGvWIC2sl7i40yvCXjDjiRnZNK9HwgL94XtALCXYRFR\nJD41bRA3MO5A0HSPIWwJXwS10/cU56HVCNHjwKa6Rz/QiG2kNASMZEMzlvHtrjna\ndx36/sjI3HH8gh1BaTZyiuDE72SMkPbL838jfL1YY9uJ0u6hWFDbdn3sqPfJ6Cnz\n1cu0piT35nkilnIGCNYA0i3lyMeo4XrdXaAJdN9nnqbCi5ewQWqaHbrIIY5LTgzJ\nYlOr3IiecyokFxHCbULXle60u0KqXYgBHmlQJJr1Dj4c9AkQmefjC2jRMlhOrIzo\nIkIUeMECgYEA+MNLB+w6vv1ogqzM3M1OLt6bziWJCn+XkziuMrCiY9KeDD+S70+E\nhfbhM5RjCE3wxC/k59039laT973BmdMHxrDd2zSjOFmCIORv5yrD5oBHMaMZcwuQ\n45Xisi4aoQoOhyznSnjo/RjeQB7qEDzXFznLLNT79HzqyAtCWD3UIu8CgYEA2yik\n9FKl7HJEY94D2K6vNh1AHGnkwIQC72pXzlUrVuwQYngj6/Gkhw8ayFBApHfwVCXj\no9rDYPdNrrAs0Zz0JsiJp6bOCEKCrMYE16UiejUUAg/OZ5eg6+3m3/iWatkzLUuK\n1LIkVBJlEyY0uPuAaBF0V0VleNvfCGhVYOn46+ECgYAUD4OsduNh5YOZDiBTKgdF\nBlSgMiyz+QgbKjX6Bn6B+EkgibvqqonwV7FffHbkA40H9SjLfe52YhL6poXHRtpY\nroillcAX2jgBOQrBJJS5sNyM5y81NNiRUdP/NHKXS/1R71ATlF6NkoTRvOx5NL7P\ns6xryB0tYSl5ylamUQ4bZwKBgHF6FB9mA//wErVbKcayfIqajq2nrwh30kVBXQG7\nW9uAE+PIrWDoF/bOvWFnHHGMoOYRUFNxXKUCqDiBhFNs34aNY6lpV1kzhxIK3ksC\neF2qyhdfM9Kz0mEXJ+pkfw4INNWJPfNv4hueArPtnnMB1rUMBJ+DkU0JG+zwiPTL\ncVZBAoGBAM6kOsh5KGn3aI83g9ZO0TrKLXXFotxJt31Wu11ydj9K33/Qj3UXcxd4\nJPXr600F0DkLeUKBob6BALeHFWcrSz5FGLGRqdRxdv+L6g18WH5m2xEs7o6M6e5I\nIhyUC60ZewJ2M8rV4KgCJJdZE2kENlSgjU92IDVPT9Oetrc7hQJd\n-----END RSA PRIVATE KEY-----\n\n"
  end
end
