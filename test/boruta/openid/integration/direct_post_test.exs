defmodule Boruta.OpenidTest.DirectPostTest do
  use Boruta.DataCase

  import Boruta.Factory
  import Mox

  alias Boruta.Ecto.Client
  alias Boruta.Oauth
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Openid
  alias Boruta.Openid.ApplicationMock
  alias Boruta.Openid.VerifiablePresentations
  alias Boruta.Repo

  setup do
    stub(Boruta.Support.ResourceOwners, :from_holder, fn %{sub: sub} ->
      {:ok, %ResourceOwner{sub: sub}}
    end)

    stub(Boruta.Support.ResourceOwners, :authorized_scopes, fn _resource_owner ->
      []
    end)

    :ok
  end

  describe "authenticates with direct post response" do
    setup do
      {:ok, client} = Repo.get_by(Client, public_client_id: Boruta.Config.issuer())
      |> Ecto.Changeset.change(%{check_public_client_id: true})
      |> Repo.update()

      wallet_did =
        "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ"

      pkce_client = insert(:client, pkce: true, redirect_uris: ["https://redirect.uri"])

      code_params = [
        type: "code",
        client: client,
        redirect_uri: "http://redirect.uri",
        relying_party_redirect_uri: "http://relying.party.redirect.uri",
        state: "state",
        sub: wallet_did,
        presentation_definition: %{
          "id" => "test",
          "format" => %{"jwt_vc" => %{"alg" => ["ES256'"]}, "jwt_vp" => %{"alg" => ["ES256"]}},
          "input_descriptors" => [
            %{
              "id" => "test",
              "format" => %{"jwt_vc" => %{"alg" => ["ES256"]}},
              "constraints" => %{
                "fields" => [
                  %{
                    "path" => ["$.vc.type"],
                    "filter" => %{
                      "type" => "array",
                      "contains" => %{"const" => "VerifiableAttestation"}
                    }
                  }
                ]
              }
            }
          ]
        }
      ]

      code = insert(:token, [{:public_client_id, wallet_did} | code_params])

      bad_public_client_code = insert(:token, [{:public_client_id, "did:key:test"} | code_params])

      public_client_code = insert(:token, [{:public_client_id, wallet_did} | code_params])

      pkce_code =
        insert(:token,
          type: "code",
          client: pkce_client,
          code_challenge: "code challenge",
          code_challenge_hash: Oauth.Token.hash("code challenge"),
          code_challenge_method: "plain",
          redirect_uri: "http://redirect.uri",
          state: "state",
          sub: wallet_did,
          presentation_definition: %{
            "id" => "test",
            "format" => %{"jwt_vc" => %{"alg" => ["ES256'"]}, "jwt_vp" => %{"alg" => ["ES256"]}},
            "input_descriptors" => [
              %{
                "id" => "test",
                "format" => %{"jwt_vc" => %{"alg" => ["ES256"]}},
                "constraints" => %{
                  "fields" => [
                    %{
                      "path" => ["$.vc.type"],
                      "filter" => %{
                        "type" => "array",
                        "contains" => %{"const" => "VerifiableAttestation"}
                      }
                    }
                  ]
                }
              }
            ]
          }
        )

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "kid" => wallet_did,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, id_token, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "iss" =>
              "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ"
          },
          signer
        )

      {:ok, credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => :os.system_time(:second) + 10,
            "sub" => "did:key:test",
            "vc" => %{
              "validFrom" => DateTime.utc_now() |> DateTime.add(-10) |> DateTime.to_iso8601(),
              "type" => ["VerifiableAttestation"]
            }
          },
          signer
        )

      {:ok, vp_token, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "iss" =>
              "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ",
            "vp" => %{
              "verifiableCredential" => [credential]
            }
          },
          signer
        )

      {:ok,
       client: client,
       code: code,
       pkce_code: pkce_code,
       public_client_code: public_client_code,
       bad_public_client_code: bad_public_client_code,
       id_token: id_token,
       vp_token: vp_token}
    end

    test "returns authentication failure without id_token" do
      conn = %Plug.Conn{}

      assert {
               :authentication_failure,
               %Boruta.Oauth.Error{
                 status: :unauthorized,
                 format: :query,
                 error: :unauthorized,
                 error_description: "id_token or vp_token param missing."
               }
             } =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: "bad_code_id"
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - returns not found with a bad id_token" do
      conn = %Plug.Conn{}

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :unauthorized,
                format: :query,
                error: :unauthorized,
                error_description: "{:error, :token_malformed}"
              }} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: "bad_code_id",
                   id_token: "bad_id_token"
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - returns not found with a bad code", %{id_token: id_token} do
      conn = %Plug.Conn{}

      assert {:code_not_found} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: "bad_code_id",
                   id_token: id_token
                 },
                 ApplicationMock
               )
    end

    @tag :skip
    test "siopv2 - retruns an error when code subject does not match", %{id_token: id_token} do
      code =
        insert(:token,
          type: "code",
          redirect_uri: "http://redirect.uri",
          state: "state",
          sub: "did:jwk:other"
        )

      conn = %Plug.Conn{}

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                format: :query,
                error: :invalid_request,
                status: :bad_request,
                error_description: "Code subject do not match with provided id_token or vp_token"
              }} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token: id_token
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - returns an error with expired code", %{id_token: id_token} do
      code = insert(:token, type: "code", expires_at: 0)
      conn = %Plug.Conn{}

      assert {
               :authentication_failure,
               %Boruta.Oauth.Error{
                 status: :bad_request,
                 format: :query,
                 error: :invalid_grant,
                 error_description: "Given authorization code is invalid, revoked, or expired."
               }
             } =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token: id_token
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - returns an error on replay", %{id_token: id_token, code: code} do
      conn = %Plug.Conn{}

      assert {:direct_post_success, _response} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token: id_token
                 },
                 ApplicationMock
               )

      assert {
               :authentication_failure,
               %Boruta.Oauth.Error{
                 status: :bad_request,
                 format: :query,
                 error: :invalid_grant,
                 error_description: "Given authorization code is invalid, revoked, or expired."
               }
             } =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token: id_token
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - returns an error with pkce client without code_verifier", %{
      id_token: id_token,
      pkce_code: code
    } do
      conn = %Plug.Conn{}

      assert {
               :authentication_failure,
               %Boruta.Oauth.Error{
                 error: :invalid_request,
                 error_description: "Code verifier is invalid.",
                 format: :query,
                 redirect_uri: "http://redirect.uri",
                 state: "state",
                 status: :bad_request
               }
             } =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token: id_token
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - returns an error with pkce client with bad code_verifier", %{
      id_token: id_token,
      pkce_code: code
    } do
      conn = %Plug.Conn{}

      assert {
               :authentication_failure,
               %Boruta.Oauth.Error{
                 error: :invalid_request,
                 error_description: "Code verifier is invalid.",
                 format: :query,
                 redirect_uri: "http://redirect.uri",
                 state: "state",
                 status: :bad_request
               }
             } =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token: id_token,
                   code_verifier: "bad code verifier"
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - authenticates with bad public client", %{
      id_token: id_token,
      bad_public_client_code: code
    } do
      conn = %Plug.Conn{}

      assert {:direct_post_success, _response} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token: id_token
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - authenticates", %{id_token: id_token, code: code} do
      conn = %Plug.Conn{}

      assert {:direct_post_success, response} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token: id_token
                 },
                 ApplicationMock
               )

      assert response.id_token
      assert response.redirect_uri == code.redirect_uri
      assert response.code.value == code.value
      assert response.state == code.state
    end

    test "siopv2 - authenticates with public client", %{
      id_token: id_token,
      public_client_code: code
    } do
      conn = %Plug.Conn{}

      assert {:direct_post_success, response} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token: id_token
                 },
                 ApplicationMock
               )

      assert response.id_token
      assert response.redirect_uri == code.redirect_uri
      assert response.code.value == code.value
      assert response.state == code.state
    end

    test "siopv2 - authenticates with code verifier (plain code challenge)", %{
      id_token: id_token,
      pkce_code: code
    } do
      conn = %Plug.Conn{}

      assert {:direct_post_success, response} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   id_token: id_token,
                   code_verifier: code.code_challenge
                 },
                 ApplicationMock
               )

      assert response.id_token
      assert response.redirect_uri == code.redirect_uri
      assert response.code.value == code.value
      assert response.state == code.state
    end

    test "oid4vp - returns not found with a bad id_token" do
      conn = %Plug.Conn{}

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :unauthorized,
                format: :query,
                error: :unauthorized,
                error_description: "{:error, :token_malformed}"
              }} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: "bad_code_id",
                   vp_token: "bad_vp_token"
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - returns not found with a bad code", %{vp_token: vp_token} do
      conn = %Plug.Conn{}

      assert {:code_not_found} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: "bad_code_id",
                   vp_token: vp_token
                 },
                 ApplicationMock
               )
    end

    @tag :skip
    test "oid4vp - retruns an error when code subject does not match", %{vp_token: vp_token} do
      code =
        insert(:token,
          type: "code",
          redirect_uri: "http://redirect.uri",
          state: "state",
          sub: "did:jwk:other"
        )

      conn = %Plug.Conn{}

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                format: :query,
                error: :invalid_request,
                status: :bad_request,
                error_description: "Code subject do not match with provided id_token or vp_token"
              }} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   vp_token: vp_token
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - returns an error with expired code", %{vp_token: vp_token} do
      code = insert(:token, type: "code", expires_at: 0)
      conn = %Plug.Conn{}

      presentation_submission =
        Jason.encode!(%{
          "id" => "test",
          "definition_id" => "test",
          "descriptor_map" => [
            %{
              "id" => "test",
              "format" => "jwt_vp",
              "path" => "$",
              "path_nested" => %{
                "id" => "test",
                "format" => "jwt_vc",
                "path" => "$.vp.verifiableCredential[0]"
              }
            }
          ]
        })

      assert {
               :authentication_failure,
               %Boruta.Oauth.Error{
                 status: :bad_request,
                 format: :query,
                 error: :invalid_grant,
                 error_description: "Given authorization code is invalid, revoked, or expired."
               }
             } =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: presentation_submission
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - returns an error on replay", %{vp_token: vp_token, code: code} do
      conn = %Plug.Conn{}

      presentation_submission =
        Jason.encode!(%{
          "id" => "test",
          "definition_id" => "test",
          "descriptor_map" => [
            %{
              "id" => "test",
              "format" => "jwt_vp",
              "path" => "$",
              "path_nested" => %{
                "id" => "test",
                "format" => "jwt_vc",
                "path" => "$.vp.verifiableCredential[0]"
              }
            }
          ]
        })

      assert {:direct_post_success, _response} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: presentation_submission
                 },
                 ApplicationMock
               )

      assert {
               :authentication_failure,
               %Boruta.Oauth.Error{
                 status: :bad_request,
                 format: :query,
                 error: :invalid_grant,
                 error_description: "Given authorization code is invalid, revoked, or expired."
               }
             } =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: presentation_submission
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - returns an error with pkce client without code_verifier", %{
      vp_token: vp_token,
      pkce_code: code
    } do
      conn = %Plug.Conn{}

      presentation_submission =
        Jason.encode!(%{
          "id" => "test",
          "definition_id" => "test",
          "descriptor_map" => [
            %{
              "id" => "test",
              "format" => "jwt_vp",
              "path" => "$",
              "path_nested" => %{
                "id" => "test",
                "format" => "jwt_vc",
                "path" => "$.vp.verifiableCredential[0]"
              }
            }
          ]
        })

      assert {
               :authentication_failure,
               %Boruta.Oauth.Error{
                 error: :invalid_request,
                 error_description: "Code verifier is invalid.",
                 format: :query,
                 redirect_uri: "http://redirect.uri",
                 state: "state",
                 status: :bad_request
               }
             } =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   presentation_submission: presentation_submission,
                   vp_token: vp_token
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - returns an error with pkce client with bad code_verifier", %{
      vp_token: vp_token,
      pkce_code: code
    } do
      conn = %Plug.Conn{}

      presentation_submission =
        Jason.encode!(%{
          "id" => "test",
          "definition_id" => "test",
          "descriptor_map" => [
            %{
              "id" => "test",
              "format" => "jwt_vp",
              "path" => "$",
              "path_nested" => %{
                "id" => "test",
                "format" => "jwt_vc",
                "path" => "$.vp.verifiableCredential[0]"
              }
            }
          ]
        })

      assert {
               :authentication_failure,
               %Boruta.Oauth.Error{
                 error: :invalid_request,
                 error_description: "Code verifier is invalid.",
                 format: :query,
                 redirect_uri: "http://redirect.uri",
                 state: "state",
                 status: :bad_request
               }
             } =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: presentation_submission,
                   code_verifier: "bad code verifier"
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - returns an error with bad public client", %{
      vp_token: vp_token,
      bad_public_client_code: code
    } do
      conn = %Plug.Conn{}

      presentation_submission =
        Jason.encode!(%{
          "id" => "test",
          "definition_id" => "test",
          "descriptor_map" => [
            %{
              "id" => "test",
              "format" => "jwt_vp",
              "path" => "$",
              "path_nested" => %{
                "id" => "test",
                "format" => "jwt_vc",
                "path" => "$.vp.verifiableCredential[0]"
              }
            }
          ]
        })

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :bad_request,
                error: :invalid_client,
                error_description:
                  "Authorization client_id do not match vp_token signature.",
                format: :query,
                redirect_uri: "http://redirect.uri",
                state: "state"
              }} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: presentation_submission
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - authenticates", %{vp_token: vp_token, code: code} do
      conn = %Plug.Conn{}

      presentation_submission =
        Jason.encode!(%{
          "id" => "test",
          "definition_id" => "test",
          "descriptor_map" => [
            %{
              "id" => "test",
              "format" => "jwt_vp",
              "path" => "$",
              "path_nested" => %{
                "id" => "test",
                "format" => "jwt_vc",
                "path" => "$.vp.verifiableCredential[0]"
              }
            }
          ]
        })

      assert {:direct_post_success, response} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: presentation_submission
                 },
                 ApplicationMock
               )

      assert response.vp_token
      assert response.redirect_uri == code.redirect_uri
      assert response.code.value == code.value
      assert response.state == code.state
      assert response.token.redirect_uri == code.relying_party_redirect_uri
    end

    test "oid4vp - authenticates with a public client", %{
      vp_token: vp_token,
      public_client_code: code
    } do
      conn = %Plug.Conn{}

      presentation_submission =
        Jason.encode!(%{
          "id" => "test",
          "definition_id" => "test",
          "descriptor_map" => [
            %{
              "id" => "test",
              "format" => "jwt_vp",
              "path" => "$",
              "path_nested" => %{
                "id" => "test",
                "format" => "jwt_vc",
                "path" => "$.vp.verifiableCredential[0]"
              }
            }
          ]
        })

      assert {:direct_post_success, response} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: presentation_submission
                 },
                 ApplicationMock
               )

      assert response.vp_token
      assert response.redirect_uri == code.redirect_uri
      assert response.code.value == code.value
      assert response.state == code.state
    end

    test "oid4vp - authenticates with code verifier (plain code challenge)", %{
      vp_token: vp_token,
      pkce_code: code
    } do
      conn = %Plug.Conn{}

      presentation_submission =
        Jason.encode!(%{
          "id" => "test",
          "definition_id" => "test",
          "descriptor_map" => [
            %{
              "id" => "test",
              "format" => "jwt_vp",
              "path" => "$",
              "path_nested" => %{
                "id" => "test",
                "format" => "jwt_vc",
                "path" => "$.vp.verifiableCredential[0]"
              }
            }
          ]
        })

      assert {:direct_post_success, response} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: presentation_submission,
                   code_verifier: code.code_challenge
                 },
                 ApplicationMock
               )

      assert response.vp_token
      assert response.redirect_uri == code.redirect_uri
      assert response.code.value == code.value
      assert response.state == code.state
    end
  end

  def public_key_fixture do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def private_key_fixture do
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVO\nf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa\n9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8Wd\nSq3dGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/\nU8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2t\npyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQABAoIBAG0dg/upL8k1IWiv\n8BNphrXIYLYQmiiBQTPJWZGvWIC2sl7i40yvCXjDjiRnZNK9HwgL94XtALCXYRFR\nJD41bRA3MO5A0HSPIWwJXwS10/cU56HVCNHjwKa6Rz/QiG2kNASMZEMzlvHtrjna\ndx36/sjI3HH8gh1BaTZyiuDE72SMkPbL838jfL1YY9uJ0u6hWFDbdn3sqPfJ6Cnz\n1cu0piT35nkilnIGCNYA0i3lyMeo4XrdXaAJdN9nnqbCi5ewQWqaHbrIIY5LTgzJ\nYlOr3IiecyokFxHCbULXle60u0KqXYgBHmlQJJr1Dj4c9AkQmefjC2jRMlhOrIzo\nIkIUeMECgYEA+MNLB+w6vv1ogqzM3M1OLt6bziWJCn+XkziuMrCiY9KeDD+S70+E\nhfbhM5RjCE3wxC/k59039laT973BmdMHxrDd2zSjOFmCIORv5yrD5oBHMaMZcwuQ\n45Xisi4aoQoOhyznSnjo/RjeQB7qEDzXFznLLNT79HzqyAtCWD3UIu8CgYEA2yik\n9FKl7HJEY94D2K6vNh1AHGnkwIQC72pXzlUrVuwQYngj6/Gkhw8ayFBApHfwVCXj\no9rDYPdNrrAs0Zz0JsiJp6bOCEKCrMYE16UiejUUAg/OZ5eg6+3m3/iWatkzLUuK\n1LIkVBJlEyY0uPuAaBF0V0VleNvfCGhVYOn46+ECgYAUD4OsduNh5YOZDiBTKgdF\nBlSgMiyz+QgbKjX6Bn6B+EkgibvqqonwV7FffHbkA40H9SjLfe52YhL6poXHRtpY\nroillcAX2jgBOQrBJJS5sNyM5y81NNiRUdP/NHKXS/1R71ATlF6NkoTRvOx5NL7P\ns6xryB0tYSl5ylamUQ4bZwKBgHF6FB9mA//wErVbKcayfIqajq2nrwh30kVBXQG7\nW9uAE+PIrWDoF/bOvWFnHHGMoOYRUFNxXKUCqDiBhFNs34aNY6lpV1kzhxIK3ksC\neF2qyhdfM9Kz0mEXJ+pkfw4INNWJPfNv4hueArPtnnMB1rUMBJ+DkU0JG+zwiPTL\ncVZBAoGBAM6kOsh5KGn3aI83g9ZO0TrKLXXFotxJt31Wu11ydj9K33/Qj3UXcxd4\nJPXr600F0DkLeUKBob6BALeHFWcrSz5FGLGRqdRxdv+L6g18WH5m2xEs7o6M6e5I\nIhyUC60ZewJ2M8rV4KgCJJdZE2kENlSgjU92IDVPT9Oetrc7hQJd\n-----END RSA PRIVATE KEY-----\n\n"
  end
end
