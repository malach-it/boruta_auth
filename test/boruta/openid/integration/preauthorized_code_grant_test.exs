defmodule Boruta.OauthTest.PreauthorizedCodeGrantTest do
  use Boruta.DataCase

  import Boruta.Factory
  import Mox

  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.TokenResponse
  alias Boruta.Openid.CredentialOfferResponse
  alias Boruta.Support.ResourceOwners
  alias Boruta.Support.User

  setup :verify_on_exit!

  describe "authorization code grant - authorize" do
    setup do
      user = %User{}
      resource_owner = %ResourceOwner{sub: user.id, username: user.email}
      client = insert(:client, redirect_uris: ["https://redirect.uri"])

      confidential_client =
        insert(:client, redirect_uris: ["https://redirect.uri"], confidential: true)

      wildcard_redirect_uri_client = insert(:client, redirect_uris: ["https://*.uri"])
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
       resource_owner: resource_owner}
    end

    test "returns an error if `response_type` is preauthorized and schema is invalid" do
      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "urn:ietf:params:oauth:response-type:pre-authorized_code"
                 }
               },
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
                   "response_type" => "urn:ietf:params:oauth:response-type:pre-authorized_code",
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

    test "returns an error if user is invalid", %{client: client} do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "urn:ietf:params:oauth:response-type:pre-authorized_code",
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

    #     test "returns an error from Ecto", %{client: client, resource_owner: resource_owner} do
    #       resource_owner = %{resource_owner | sub: 1}
    #
    #       redirect_uri = List.first(client.redirect_uris)
    #
    #       assert {
    #                :authorize_error,
    #                %Boruta.Oauth.Error{
    #                  error: :unknown_error,
    #                  error_description: "\"Could not create code : sub is invalid\"",
    #                  format: :fragment,
    #                  redirect_uri: "https://redirect.uri",
    #                  state: nil,
    #                  status: :internal_server_error
    #                }
    #              } =
    #                Oauth.authorize(
    #                  %Plug.Conn{
    #                    query_params: %{
    #                      "response_type" => "urn:ietf:params:oauth:response-type:pre-authorized_code",
    #                      "client_id" => client.id,
    #                      "redirect_uri" => redirect_uri
    #                    }
    #                  },
    #                  resource_owner,
    #                  ApplicationMock
    #                )
    #     end

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
                   "response_type" => "urn:ietf:params:oauth:response-type:pre-authorized_code",
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

    test "returns an error if grant type is not allowed by client", %{
      client_without_grant_type: client,
      resource_owner: resource_owner
    } do
      redirect_uri = List.first(client.redirect_uris)

      assert Oauth.authorize(
               %Plug.Conn{
                 query_params: %{
                   "response_type" => "urn:ietf:params:oauth:response-type:pre-authorized_code",
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

    test "returns a credential offer response (draft 13)", %{client: client, resource_owner: resource_owner} do
      redirect_uri = List.first(client.redirect_uris)

      resource_owner = %{
        resource_owner
        | authorization_details: [
            %{
              "credential_configuration_id" => "credential"
            }
          ]
      }

      assert {:authorize_success,
              %CredentialOfferResponse{
                credential_issuer: "boruta",
                credential_configuration_ids: ["credential"],
                grants: %{
                  "urn:ietf:params:oauth:grant-type:pre-authorized_code" => %{
                    "pre-authorized_code" => preauthorized_code
                  }
                }
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "urn:ietf:params:oauth:response-type:pre-authorized_code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert preauthorized_code
    end

    test "returns a credential offer response (draft 11)", %{client: client, resource_owner: resource_owner} do
      redirect_uri = List.first(client.redirect_uris)

      resource_owner = %{
        resource_owner
        | authorization_details: [
            %{
              "credential_identifiers" => ["credential", "test", "c"]
            }
        ],
        credential_configuration: %{
          "credentialjwtvc" => %{
            format: "jwt_vc",
            types: ["credential", "test"]
          },
          "credentialsdjwt" => %{
            format: "vc+sd-jwt",
            types: ["credential", "test"]
          },
          "credentialsc" => %{
            format: "vc+sd-jwt",
            types: ["credential", "test", "c"]
          }
        }
      }

      assert {:authorize_success,
              %CredentialOfferResponse{
                credential_issuer: "boruta",
                credentials: [
                  %{format: "jwt_vc", types: ["credential", "test"]},
                  %{format: "vc+sd-jwt", types: ["credential", "test", "c"]}
                ],
                grants: %{
                  "urn:ietf:params:oauth:grant-type:pre-authorized_code" => %{
                    "pre-authorized_code" => preauthorized_code
                  }
                }
              }} =
               Oauth.authorize(
                 %Plug.Conn{
                   query_params: %{
                     "response_type" => "urn:ietf:params:oauth:response-type:pre-authorized_code",
                     "client_id" => client.id,
                     "redirect_uri" => redirect_uri
                   }
                 },
                 resource_owner,
                 ApplicationMock
               )

      assert preauthorized_code
    end

    #     test "returns a code with a confidential client", %{
    #       confidential_client: client,
    #       resource_owner: resource_owner
    #     } do
    #       redirect_uri = List.first(client.redirect_uris)
    #
    #       assert {:authorize_success,
    #               %AuthorizeResponse{
    #                 type: type,
    #                 code: value,
    #                 expires_in: expires_in
    #               }} =
    #                Oauth.authorize(
    #                  %Plug.Conn{
    #                    query_params: %{
    #                      "response_type" => "code",
    #                      "client_id" => client.id,
    #                      "redirect_uri" => redirect_uri
    #                    }
    #                  },
    #                  resource_owner,
    #                  ApplicationMock
    #                )
    #
    #       assert type == :code
    #       assert value
    #       assert expires_in
    #     end
    #
    #     test "returns a code with a wildcard client redirect uri", %{
    #       wildcard_redirect_uri_client: client,
    #       resource_owner: resource_owner
    #     } do
    #       redirect_uri = "https://wildcard-redirect-uri.uri"
    #
    #       assert {:authorize_success,
    #               %AuthorizeResponse{
    #                 type: type,
    #                 code: value,
    #                 expires_in: expires_in
    #               }} =
    #                Oauth.authorize(
    #                  %Plug.Conn{
    #                    query_params: %{
    #                      "response_type" => "code",
    #                      "client_id" => client.id,
    #                      "redirect_uri" => redirect_uri
    #                    }
    #                  },
    #                  resource_owner,
    #                  ApplicationMock
    #                )
    #
    #       assert type == :code
    #       assert value
    #       assert expires_in
    #     end
    #
    #     test "nonce is stored in code", %{client: client, resource_owner: resource_owner} do
    #       redirect_uri = List.first(client.redirect_uris)
    #       nonce = "nonce"
    #
    #       Oauth.authorize(
    #         %Plug.Conn{
    #           query_params: %{
    #             "response_type" => "code",
    #             "client_id" => client.id,
    #             "redirect_uri" => redirect_uri,
    #             "nonce" => nonce
    #           }
    #         },
    #         resource_owner,
    #         ApplicationMock
    #       )
    #
    #       assert %Ecto.Token{nonce: ^nonce} = Repo.get_by(Ecto.Token, type: "code")
    #     end
    #
    #     test "returns a code with public scope", %{client: client, resource_owner: resource_owner} do
    #       ResourceOwners
    #       |> expect(:authorized_scopes, fn _resource_owner -> [] end)
    #
    #       given_scope = "public"
    #       redirect_uri = List.first(client.redirect_uris)
    #
    #       case Oauth.authorize(
    #              %Plug.Conn{
    #                query_params: %{
    #                  "response_type" => "code",
    #                  "client_id" => client.id,
    #                  "redirect_uri" => redirect_uri,
    #                  "scope" => given_scope
    #                }
    #              },
    #              resource_owner,
    #              ApplicationMock
    #            ) do
    #         {:authorize_success,
    #          %AuthorizeResponse{
    #            type: type,
    #            code: value,
    #            expires_in: expires_in
    #          }} ->
    #           assert type == :code
    #           assert value
    #           assert expires_in
    #
    #         _ ->
    #           assert false
    #       end
    #     end
    #
    #     test "returns a code with public scope (from cache)", %{
    #       client: client,
    #       resource_owner: resource_owner
    #     } do
    #       ResourceOwners
    #       |> expect(:authorized_scopes, fn _resource_owner -> [] end)
    #
    #       given_scope = "public"
    #       redirect_uri = List.first(client.redirect_uris)
    #       ScopeStore.put_public([%Scope{name: "public"}])
    #
    #       case Oauth.authorize(
    #              %Plug.Conn{
    #                query_params: %{
    #                  "response_type" => "code",
    #                  "client_id" => client.id,
    #                  "redirect_uri" => redirect_uri,
    #                  "scope" => given_scope
    #                }
    #              },
    #              resource_owner,
    #              ApplicationMock
    #            ) do
    #         {:authorize_success,
    #          %AuthorizeResponse{
    #            type: type,
    #            code: value,
    #            expires_in: expires_in
    #          }} ->
    #           assert type == :code
    #           assert value
    #           assert expires_in
    #
    #         _ ->
    #           assert false
    #       end
    #     end
    #
    #     test "returns an error with private scope", %{client: client, resource_owner: resource_owner} do
    #       ResourceOwners
    #       |> expect(:authorized_scopes, fn _resource_owner -> [] end)
    #
    #       given_scope = "private"
    #       redirect_uri = List.first(client.redirect_uris)
    #
    #       assert Oauth.authorize(
    #                %Plug.Conn{
    #                  query_params: %{
    #                    "response_type" => "code",
    #                    "client_id" => client.id,
    #                    "redirect_uri" => redirect_uri,
    #                    "scope" => given_scope
    #                  }
    #                },
    #                resource_owner,
    #                ApplicationMock
    #              ) ==
    #                {:authorize_error,
    #                 %Error{
    #                   error: :invalid_scope,
    #                   error_description: "Given scopes are unknown or unauthorized.",
    #                   status: :bad_request,
    #                   format: :query,
    #                   redirect_uri: redirect_uri
    #                 }}
    #     end
    #
    #     test "returns a code if scope is authorized by client", %{
    #       client_with_scope: client,
    #       resource_owner: resource_owner
    #     } do
    #       ResourceOwners
    #       |> expect(:authorized_scopes, fn _resource_owner -> [] end)
    #
    #       %{name: given_scope} = List.first(client.authorized_scopes)
    #       redirect_uri = List.first(client.redirect_uris)
    #
    #       case Oauth.authorize(
    #              %Plug.Conn{
    #                query_params: %{
    #                  "response_type" => "code",
    #                  "client_id" => client.id,
    #                  "redirect_uri" => redirect_uri,
    #                  "scope" => given_scope
    #                }
    #              },
    #              resource_owner,
    #              ApplicationMock
    #            ) do
    #         {:authorize_success,
    #          %AuthorizeResponse{
    #            type: type,
    #            code: value,
    #            expires_in: expires_in
    #          }} ->
    #           assert type == :code
    #           assert value
    #           assert expires_in
    #
    #         _ ->
    #           assert false
    #       end
    #     end
    #
    #     test "returns a code if scope is authorized by resource owner", %{
    #       client_with_scope: client,
    #       resource_owner: resource_owner
    #     } do
    #       given_scope = %Scope{name: "resource_owner:scope"}
    #
    #       ResourceOwners
    #       |> expect(:authorized_scopes, fn _resource_owner -> [given_scope] end)
    #
    #       redirect_uri = List.first(client.redirect_uris)
    #
    #       case Oauth.authorize(
    #              %Plug.Conn{
    #                query_params: %{
    #                  "response_type" => "code",
    #                  "client_id" => client.id,
    #                  "redirect_uri" => redirect_uri,
    #                  "scope" => given_scope.name
    #                }
    #              },
    #              resource_owner,
    #              ApplicationMock
    #            ) do
    #         {:authorize_success,
    #          %AuthorizeResponse{
    #            type: type,
    #            code: value,
    #            expires_in: expires_in
    #          }} ->
    #           assert type == :code
    #           assert value
    #           assert expires_in
    #
    #         _ ->
    #           assert false
    #       end
    #     end
    #
    #     test "returns a code with state", %{client: client, resource_owner: resource_owner} do
    #       given_state = "state"
    #       redirect_uri = List.first(client.redirect_uris)
    #
    #       case Oauth.authorize(
    #              %Plug.Conn{
    #                query_params: %{
    #                  "response_type" => "code",
    #                  "client_id" => client.id,
    #                  "redirect_uri" => redirect_uri,
    #                  "state" => given_state
    #                }
    #              },
    #              resource_owner,
    #              ApplicationMock
    #            ) do
    #         {:authorize_success,
    #          %AuthorizeResponse{
    #            type: type,
    #            code: value,
    #            expires_in: expires_in,
    #            state: state
    #          }} ->
    #           assert type == :code
    #           assert value
    #           assert expires_in
    #           assert state == given_state
    #
    #         _ ->
    #           assert false
    #       end
    #     end
  end

  describe "preauthorization code grant - token" do
    setup do
      user = %User{}
      resource_owner = %ResourceOwner{sub: user.id, username: user.email}
      client = insert(:client)

      code =
        insert(
          :token,
          type: "preauthorized_code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          authorization_details: [
            %{
              "credential_definition" => %{
                "type" => ["credential"]
              }
            }
          ]
        )

      openid_code =
        insert(
          :token,
          type: "preauthorized_code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          scope: "openid",
          nonce: "nonce"
        )

      expired_code =
        insert(
          :token,
          type: "preauthorized_code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          expires_at: :os.system_time(:seconds) - 10
        )

      revoked_code =
        insert(
          :token,
          type: "preauthorized_code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          revoked_at: DateTime.utc_now()
        )

      bad_redirect_uri_code =
        insert(
          :token,
          type: "preauthorized_code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: "http://bad.redirect.uri"
        )

      code_with_scope =
        insert(
          :token,
          type: "preauthorized_code",
          client: client,
          sub: resource_owner.sub,
          redirect_uri: List.first(client.redirect_uris),
          scope: "hello world"
        )

      {:ok,
       resource_owner: resource_owner,
       code: code,
       expired_code: expired_code,
       revoked_code: revoked_code,
       openid_code: openid_code,
       bad_redirect_uri_code: bad_redirect_uri_code,
       code_with_scope: code_with_scope}
    end

    test "returns an error if request is invalid" do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "urn:ietf:params:oauth:grant-type:pre-authorized_code"
                 }
               },
               ApplicationMock
             ) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request body validation failed. " <>
                      "Required property pre-authorized_code is missing at #.",
                  status: :bad_request
                }}
    end

    test "returns an error if `code` is invalid" do
      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                   "pre-authorized_code" => "bad_code"
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

    test "returns an error when code is expired", %{
      expired_code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 1, fn _params -> {:ok, resource_owner} end)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                   "pre-authorized_code" => code.value
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
      revoked_code: code,
      resource_owner: resource_owner
    } do
      ResourceOwners
      |> expect(:get_by, 1, fn _params -> {:ok, resource_owner} end)

      assert Oauth.token(
               %Plug.Conn{
                 body_params: %{
                   "grant_type" => "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                   "pre-authorized_code" => code.value
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

    test "returns a token", %{code: code, resource_owner: resource_owner} do
      ResourceOwners
      |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)

      assert {:token_success,
              %TokenResponse{
                token_type: token_type,
                access_token: access_token,
                expires_in: expires_in,
                refresh_token: refresh_token,
                authorization_details: authorization_details
              }} =
               Oauth.token(
                 %Plug.Conn{
                   body_params: %{
                     "grant_type" => "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                     "pre-authorized_code" => code.value
                   }
                 },
                 ApplicationMock
               )

      assert token_type == "bearer"
      assert access_token
      assert authorization_details
      assert expires_in
      assert refresh_token
    end

    #
    #     test "stores previous code", %{client: client, code: code, resource_owner: resource_owner} do
    #       ResourceOwners
    #       |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)
    #
    #       redirect_uri = List.first(client.redirect_uris)
    #
    #       assert {:token_success,
    #               %TokenResponse{
    #                 access_token: access_token
    #               }} =
    #                Oauth.token(
    #                  %Plug.Conn{
    #                    body_params: %{
    #                      "grant_type" => "authorization_code",
    #                      "client_id" => client.id,
    #                      "code" => code.value,
    #                      "redirect_uri" => redirect_uri
    #                    }
    #                  },
    #                  ApplicationMock
    #                )
    #
    #       assert token = Repo.get_by(Ecto.Token, value: access_token)
    #       assert token.previous_code == code.value
    #     end
    #
    #     test "returns a token with a confidential client", %{
    #       confidential_client: client,
    #       confidential_code: code,
    #       resource_owner: resource_owner
    #     } do
    #       ResourceOwners
    #       |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)
    #
    #       redirect_uri = List.first(client.redirect_uris)
    #
    #       case Oauth.token(
    #              %Plug.Conn{
    #                body_params: %{
    #                  "grant_type" => "authorization_code",
    #                  "client_id" => client.id,
    #                  "client_secret" => client.secret,
    #                  "code" => code.value,
    #                  "redirect_uri" => redirect_uri
    #                }
    #              },
    #              ApplicationMock
    #            ) do
    #         {:token_success,
    #          %TokenResponse{
    #            token_type: token_type,
    #            access_token: access_token,
    #            expires_in: expires_in,
    #            refresh_token: refresh_token
    #          }} ->
    #           assert token_type == "bearer"
    #           assert access_token
    #           assert expires_in
    #           assert refresh_token
    #
    #         _ ->
    #           assert false
    #       end
    #     end
    #
    #     test "returns an error if token is used twice", %{
    #       client: client,
    #       code: code,
    #       resource_owner: resource_owner
    #     } do
    #       ResourceOwners
    #       |> expect(:get_by, 3, fn _params -> {:ok, resource_owner} end)
    #
    #       redirect_uri = List.first(client.redirect_uris)
    #
    #       Oauth.token(
    #         %Plug.Conn{
    #           body_params: %{
    #             "grant_type" => "authorization_code",
    #             "client_id" => client.id,
    #             "code" => code.value,
    #             "redirect_uri" => redirect_uri
    #           }
    #         },
    #         ApplicationMock
    #       )
    #
    #       assert {:token_error,
    #               %Error{
    #                 error: :invalid_grant,
    #                 error_description: "Given authorization code is invalid, revoked, or expired.",
    #                 status: :bad_request
    #               }} =
    #                Oauth.token(
    #                  %Plug.Conn{
    #                    body_params: %{
    #                      "grant_type" => "authorization_code",
    #                      "client_id" => client.id,
    #                      "code" => code.value,
    #                      "redirect_uri" => redirect_uri
    #                    }
    #                  },
    #                  ApplicationMock
    #                )
    #     end
    #
    #     test "returns a token and an id_token with openid scope", %{
    #       client: client,
    #       openid_code: code,
    #       resource_owner: resource_owner
    #     } do
    #       ResourceOwners
    #       |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)
    #       |> expect(:claims, fn _sub, _scope -> %{} end)
    #
    #       redirect_uri = List.first(client.redirect_uris)
    #
    #       case Oauth.token(
    #              %Plug.Conn{
    #                body_params: %{
    #                  "grant_type" => "authorization_code",
    #                  "client_id" => client.id,
    #                  "code" => code.value,
    #                  "redirect_uri" => redirect_uri
    #                }
    #              },
    #              ApplicationMock
    #            ) do
    #         {:token_success,
    #          %TokenResponse{
    #            token_type: token_type,
    #            access_token: access_token,
    #            id_token: id_token,
    #            expires_in: expires_in,
    #            refresh_token: refresh_token
    #          }} ->
    #           assert token_type == "bearer"
    #           assert access_token
    #           assert id_token
    #           assert expires_in
    #           assert refresh_token
    #
    #           signer =
    #             Joken.Signer.create("RS512", %{"pem" => client.private_key, "aud" => client.id})
    #
    #           {:ok, claims} = Oauth.Client.Token.verify_and_validate(id_token, signer)
    #           client_id = client.id
    #           resource_owner_id = resource_owner.sub
    #           nonce = code.nonce
    #
    #           assert %{
    #                    "aud" => ^client_id,
    #                    "iat" => _iat,
    #                    "exp" => _exp,
    #                    "sub" => ^resource_owner_id,
    #                    "nonce" => ^nonce
    #                  } = claims
    #
    #         _ ->
    #           assert false
    #       end
    #     end
    #
    #     test "returns a token from cache", %{
    #       client: client,
    #       code: code,
    #       resource_owner: resource_owner
    #     } do
    #       ResourceOwners
    #       |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)
    #
    #       redirect_uri = List.first(client.redirect_uris)
    #       Boruta.Ecto.Codes.get_by(value: code.value, redirect_uri: redirect_uri)
    #
    #       case Oauth.token(
    #              %Plug.Conn{
    #                body_params: %{
    #                  "grant_type" => "authorization_code",
    #                  "client_id" => client.id,
    #                  "code" => code.value,
    #                  "redirect_uri" => redirect_uri
    #                }
    #              },
    #              ApplicationMock
    #            ) do
    #         {:token_success,
    #          %TokenResponse{
    #            token_type: token_type,
    #            access_token: access_token,
    #            expires_in: expires_in,
    #            refresh_token: refresh_token
    #          }} ->
    #           assert token_type == "bearer"
    #           assert access_token
    #           assert expires_in
    #           assert refresh_token
    #
    #         _ ->
    #           assert false
    #       end
    #     end
    #
    #     test "returns a token with scope", %{
    #       client: client,
    #       code_with_scope: code,
    #       resource_owner: resource_owner
    #     } do
    #       ResourceOwners
    #       |> expect(:get_by, 2, fn _params -> {:ok, resource_owner} end)
    #
    #       redirect_uri = List.first(client.redirect_uris)
    #
    #       case Oauth.token(
    #              %Plug.Conn{
    #                body_params: %{
    #                  "grant_type" => "authorization_code",
    #                  "client_id" => client.id,
    #                  "code" => code.value,
    #                  "redirect_uri" => redirect_uri
    #                }
    #              },
    #              ApplicationMock
    #            ) do
    #         {:token_success,
    #          %TokenResponse{
    #            token_type: token_type,
    #            access_token: access_token,
    #            expires_in: expires_in,
    #            refresh_token: refresh_token
    #          }} ->
    #           assert token_type == "bearer"
    #           assert access_token
    #           assert expires_in
    #           assert refresh_token
    #
    #         _ ->
    #           assert false
    #       end
    #     end
  end
end
