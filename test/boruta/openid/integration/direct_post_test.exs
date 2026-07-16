defmodule Boruta.OpenidTest.DirectPostTest do
  use Boruta.DataCase, async: false

  defmodule StringFailingCodes do
    alias Boruta.Ecto.Codes

    def get_by(params), do: Codes.get_by(params)
    def update_sub(code, sub, policy), do: Codes.update_sub(code, sub, policy)
    def code_chain(code), do: Codes.code_chain(code)

    def update_client_encryption(_code, _params),
      do: {:error, "client encryption update failed"}
  end

  defmodule TermFailingCodes do
    alias Boruta.Ecto.Codes

    def get_by(params), do: Codes.get_by(params)
    def update_sub(code, sub, policy), do: Codes.update_sub(code, sub, policy)
    def code_chain(code), do: Codes.code_chain(code)
    def update_client_encryption(_code, _params), do: {:error, :storage_unavailable}
  end

  import Boruta.Factory

  alias Boruta.Ecto.Client
  alias Boruta.Ecto.ClientStore
  alias Boruta.Oauth
  alias Boruta.Oauth.Client.Crypto
  alias Boruta.Openid
  alias Boruta.Openid.ApplicationMock
  alias Boruta.Openid.VerifiablePresentations
  alias Boruta.Repo

  @presentation_definition %{
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

  @id_token_presentation_definition %{
    "id" => "id-token-presentation-definition",
    "format" => %{"jwt_vp" => %{"alg" => ["ES256K"]}},
    "input_descriptors" => [
      %{
        "id" => "id-token-input",
        "format" => %{"jwt_vc" => %{"alg" => ["ES256K"]}},
        "constraints" => %{
          "fields" => [
            %{
              "path" => ["$.vc.credentialSubject.id"],
              "filter" => %{"type" => "string"}
            }
          ]
        }
      }
    ]
  }

  describe "authenticates with direct post response" do
    setup do
      :ok = ClientStore.invalidate_public()

      {:ok, client} =
        Repo.get_by(Client, public_client_id: Boruta.Config.issuer())
        |> Ecto.Changeset.change(%{check_public_client_id: false})
        |> Repo.update()

      wallet_did = did_jwk_fixture()

      pkce_client = insert(:client, pkce: true, redirect_uris: ["https://redirect.uri"])

      code_params = [
        type: "code",
        client: client,
        redirect_uri: "http://redirect.uri",
        state: "state",
        sub: wallet_did,
        presentation_definition: @presentation_definition
      ]

      code = insert(:token, [{:public_client_id, wallet_did} | code_params])

      bad_public_client_code = insert(:token, [{:public_client_id, "did:key:test"} | code_params])

      public_client_code = insert(:token, [{:public_client_id, wallet_did} | code_params])

      last_valid_code_chain = [
        insert(
          :token,
          [{:public_client_id, wallet_did}, {:previous_code, "last_code_1"}] ++ code_params
        ),
        insert(
          :token,
          [{:previous_code, "last_code_2"}, {:value, "last_code_1"}] ++
            code_params
        ),
        insert(:token, [{:value, "last_code_2"}] ++ code_params)
      ]

      middle_valid_code_chain = [
        insert(
          :token,
          [{:public_client_id, "did:key:other"}, {:previous_code, "middle_code_1"}] ++ code_params
        ),
        insert(
          :token,
          [{:previous_code, "middle_code_2"}, {:value, "middle_code_1"}] ++
            code_params
        ),
        insert(:token, [{:sub, wallet_did}, {:value, "middle_code_2"}] ++ code_params)
      ]

      replay_code_chain = [
        insert(
          :token,
          [{:public_client_id, "did:key:other"}, {:previous_code, "middle_code_1"}] ++ code_params
        ),
        Enum.at(middle_valid_code_chain, 1),
        Enum.at(middle_valid_code_chain, 2)
      ]

      invalid_policy_code_chain = [
        insert(
          :token,
          [{:public_client_id, wallet_did}, {:previous_code, "invalid_policy_code_1"}] ++
            code_params
        ),
        insert(
          :token,
          [
            {:previous_code, "invalid_policy_code_2"},
            {:value, "invalid_policy_code_1"},
            {:metadata_policy, %{"client_id" => %{"one_of" => ["did:key:test"]}}}
          ] ++
            code_params
        ),
        insert(:token, [{:value, "invalid_policy_code_2"}] ++ code_params)
      ]

      policy_code_chain = [
        insert(
          :token,
          [{:public_client_id, wallet_did}, {:previous_code, "policy_code_1"}] ++ code_params
        ),
        insert(
          :token,
          [
            {:previous_code, "policy_code_2"},
            {:value, "policy_code_1"},
            {:metadata_policy, %{"client_id" => %{"one_of" => [wallet_did]}}}
          ] ++
            code_params
        ),
        insert(:token, [{:value, "policy_code_2"}] ++ code_params)
      ]

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
          presentation_definition: @presentation_definition
        )

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk_fixture(),
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, id_token, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "iss" => wallet_did
          },
          signer
        )

      {:ok, id_token_with_presentation_definition, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "iss" => wallet_did,
            "presentation_definition" => @id_token_presentation_definition
          },
          signer
        )

      {:ok, credential, _claims} =
        VerifiablePresentations.Token.generate_and_sign(
          %{
            "exp" => :os.system_time(:second) + 10,
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
            "iss" => wallet_did,
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
       last_valid_code_chain: last_valid_code_chain,
       middle_valid_code_chain: middle_valid_code_chain,
       replay_code_chain: replay_code_chain,
       invalid_policy_code_chain: invalid_policy_code_chain,
       policy_code_chain: policy_code_chain,
       id_token: id_token,
       id_token_with_presentation_definition: id_token_with_presentation_definition,
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

    @tag :skip
    test "siopv2 - authenticates with bad public client", %{
      id_token: id_token,
      bad_public_client_code: code
    } do
      conn = %Plug.Conn{}

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :bad_request,
                error: :invalid_client,
                error_description: "Authorization client_id do not match vp_token signature.",
                format: :query,
                redirect_uri: "http://redirect.uri",
                state: "state"
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
      assert response.presentation_definition == @presentation_definition
    end

    test "siopv2 - authenticates with presentation definition from id_token", %{
      id_token_with_presentation_definition: id_token,
      code: code
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

      code = Repo.reload(code)
      assert response.id_token
      assert response.redirect_uri == code.redirect_uri
      assert response.code.value == code.value
      assert response.state == code.state
      assert response.presentation_definition == code.presentation_definition
      assert response.presentation_definition == @id_token_presentation_definition
      refute response.presentation_definition == @presentation_definition
    end

    test "siopv2 - authenticates (jwe)", %{id_token: id_token, code: code} do
      conn = %Plug.Conn{}

      response =
        Crypto.encrypt(
          %{id_token: id_token},
          JOSE.JWK.from_pem(code.client.public_key) |> JOSE.JWK.to_map(),
          "ECDH-ES"
        )

      assert {:direct_post_success, response} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   response: response
                 },
                 ApplicationMock
               )

      assert response.id_token
      assert response.redirect_uri == code.redirect_uri
      assert response.code.value == code.value
      assert response.state == code.state
      assert response.presentation_definition == @presentation_definition
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
      assert response.presentation_definition == @presentation_definition
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
      assert response.presentation_definition == @presentation_definition
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

    @tag :skip
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
      client: client,
      vp_token: vp_token,
      bad_public_client_code: code
    } do
      on_exit(fn ->
        ClientStore.invalidate(client)
        ClientStore.invalidate_public()
      end)

      {:ok, client} =
        client
        |> Ecto.Changeset.change(%{check_public_client_id: true})
        |> Repo.update()

      :ok = ClientStore.invalidate(client)

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
                error_description: "Could not verify given token in code chain.",
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
      assert response.presentation_definition == @presentation_definition
    end

    test "oid4vp - authenticates (jwe)", %{vp_token: vp_token, code: code} do
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

      response =
        Crypto.encrypt(
          %{
            vp_token: vp_token,
            presentation_submission: presentation_submission
          },
          JOSE.JWK.from_pem(code.client.public_key) |> JOSE.JWK.to_map(),
          "ECDH-ES"
        )

      assert {:direct_post_success, response} =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: code.id,
                   response: response
                 },
                 ApplicationMock
               )

      assert response.vp_token
      assert response.redirect_uri == code.redirect_uri
      assert response.code.value == code.value
      assert response.state == code.state
      assert response.presentation_definition == @presentation_definition
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
      assert response.presentation_definition == @presentation_definition
    end

    test "oid4vp - authenticates with a code chain (last valid)", %{
      vp_token: vp_token,
      last_valid_code_chain: [code | _code_chain]
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
      assert Enum.count(response.code_chain) == 3
      assert response.state == code.state
      assert response.presentation_definition == @presentation_definition
    end

    test "oid4vp - returns an error with a code chain (policy invalid)", %{
      vp_token: vp_token,
      invalid_policy_code_chain: [code | _code_chain]
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
                 status: :unauthorized,
                 error: :unauthorized,
                 error_description: "Metadata policies check failed.",
                 format: :query,
                 redirect_uri: "http://redirect.uri",
                 state: "state"
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

    test "oid4vp - authenticates with a code chain (policy)", %{
      vp_token: vp_token,
      policy_code_chain: [code | _code_chain]
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

      assert response.presentation_definition == @presentation_definition
    end

    @tag :skip
    test "oid4vp - returns an error with a code chain (middle valid - replay)", %{
      vp_token: vp_token,
      middle_valid_code_chain: [code | _code_chain],
      replay_code_chain: [replay_code | _replay_code_chain]
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
      assert Enum.count(response.code_chain) == 3
      assert response.state == code.state
      assert response.presentation_definition == @presentation_definition

      assert {
               :authentication_failure,
               %Boruta.Oauth.Error{
                 status: :bad_request,
                 error: :invalid_client,
                 error_description: "Authorization client_id do not match vp_token signature.",
                 format: :query,
                 redirect_uri: "http://redirect.uri",
                 state: "state"
               }
             } =
               Openid.direct_post(
                 conn,
                 %{
                   code_id: replay_code.id,
                   vp_token: vp_token,
                   presentation_submission: presentation_submission
                 },
                 ApplicationMock
               )
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
      assert response.presentation_definition == @presentation_definition
    end

    test "oid4vp - returns an error without a presentation submission", %{
      vp_token: vp_token,
      code: code
    } do
      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :bad_request,
                error: :invalid_request,
                error_description: "presentation_submission query parameter is missing.",
                format: :query,
                redirect_uri: "http://redirect.uri",
                state: "state"
              }} =
               Openid.direct_post(
                 %Plug.Conn{},
                 %{code_id: code.id, vp_token: vp_token},
                 ApplicationMock
               )
    end

    test "oid4vp - returns an error with malformed presentation submission JSON", %{
      vp_token: vp_token,
      code: code
    } do
      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :bad_request,
                error: :invalid_request,
                error_description: "presentation_submission is not a valid JSON object.",
                format: :query,
                redirect_uri: "http://redirect.uri",
                state: "state"
              }} =
               Openid.direct_post(
                 %Plug.Conn{},
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: "not-json"
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - returns an error with an invalid presentation submission", %{
      vp_token: vp_token,
      code: code
    } do
      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :bad_request,
                error: :invalid_request,
                error_description: "Required properties id, descriptor_map are missing at #.",
                format: :query,
                redirect_uri: "http://redirect.uri",
                state: "state"
              }} =
               Openid.direct_post(
                 %Plug.Conn{},
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: Jason.encode!(%{})
                 },
                 ApplicationMock
               )
    end

    test "siopv2 - authenticates when a superset metadata policy matches", %{
      client: client,
      id_token: id_token
    } do
      wallet_did = did_jwk_fixture()

      [code | _code_chain] =
        code_chain_with_policy(
          client,
          wallet_did,
          %{"client_id" => %{"superset_of" => [wallet_did]}}
        )

      assert {:direct_post_success, _response} =
               Openid.direct_post(
                 %Plug.Conn{},
                 %{code_id: code.id, id_token: id_token},
                 ApplicationMock
               )
    end

    test "siopv2 - rejects a superset metadata policy that does not match", %{
      client: client,
      id_token: id_token
    } do
      [code | _code_chain] =
        code_chain_with_policy(
          client,
          did_jwk_fixture(),
          %{"client_id" => %{"superset_of" => ["did:example:unknown"]}}
        )

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :unauthorized,
                error: :unauthorized,
                error_description: "Metadata policies check failed.",
                format: :query,
                redirect_uri: "http://redirect.uri",
                state: "state"
              }} =
               Openid.direct_post(
                 %Plug.Conn{},
                 %{code_id: code.id, id_token: id_token},
                 ApplicationMock
               )
    end

    test "siopv2 - accepts a DID public client when public-client checks are enabled", %{
      id_token: id_token
    } do
      client = insert(:client, check_public_client_id: true)

      code =
        insert(:token,
          type: "code",
          client: client,
          public_client_id: "did:example:wallet",
          redirect_uri: "http://redirect.uri",
          state: "state"
        )

      assert {:direct_post_success, _response} =
               Openid.direct_post(
                 %Plug.Conn{},
                 %{code_id: code.id, id_token: id_token},
                 ApplicationMock
               )
    end

    test "siopv2 - accepts a non-DID public client identifier", %{id_token: id_token} do
      client = insert(:client, check_public_client_id: true)

      code =
        insert(:token,
          type: "code",
          client: client,
          public_client_id: "client-id",
          redirect_uri: "http://redirect.uri",
          state: "state"
        )

      assert {:direct_post_success, _response} =
               Openid.direct_post(
                 %Plug.Conn{},
                 %{code_id: code.id, id_token: id_token},
                 ApplicationMock
               )
    end

    test "returns a contextual error when a code adapter returns a string", %{
      id_token: id_token,
      code: code
    } do
      configure_codes_adapter(StringFailingCodes)

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :unprocessable_entity,
                error: :unknown_error,
                error_description: "client encryption update failed",
                format: :query,
                redirect_uri: "http://redirect.uri",
                state: "state"
              }} =
               Openid.direct_post(
                 %Plug.Conn{},
                 %{code_id: code.id, id_token: id_token},
                 ApplicationMock
               )
    end

    test "returns an inspected error when a code adapter returns another term", %{
      id_token: id_token,
      code: code
    } do
      configure_codes_adapter(TermFailingCodes)

      assert {:authentication_failure,
              %Boruta.Oauth.Error{
                status: :unprocessable_entity,
                error: :unknown_error,
                error_description: ":storage_unavailable",
                format: :query
              }} =
               Openid.direct_post(
                 %Plug.Conn{},
                 %{code_id: code.id, id_token: id_token},
                 ApplicationMock
               )
    end

    test "oid4vp - verifies the public client against the current code", %{
      code: base_code,
      vp_token: vp_token
    } do
      {:ok, wallet_did, _public_jwk} = Boruta.Did.Crypto.did_key(public_jwk_fixture())
      client = insert(:client, check_public_client_id: true)

      [code | _code_chain] =
        public_client_code_chain(
          client,
          wallet_did,
          wallet_did,
          base_code.presentation_definition
        )

      assert {:direct_post_success, _response} =
               Openid.direct_post(
                 %Plug.Conn{},
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: valid_presentation_submission()
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - falls back to verification against an earlier code", %{
      code: base_code,
      vp_token: vp_token
    } do
      {:ok, wallet_did, _public_jwk} = Boruta.Did.Crypto.did_key(public_jwk_fixture())

      unrelated_jwk =
        JOSE.JWK.generate_key({:rsa, 2048})
        |> JOSE.JWK.to_public()
        |> JOSE.JWK.to_map()
        |> elem(1)

      {:ok, unrelated_did, _public_jwk} = Boruta.Did.Crypto.did_key(unrelated_jwk)
      client = insert(:client, check_public_client_id: true)

      [code | _code_chain] =
        public_client_code_chain(
          client,
          unrelated_did,
          wallet_did,
          base_code.presentation_definition
        )

      assert {:direct_post_success, _response} =
               Openid.direct_post(
                 %Plug.Conn{},
                 %{
                   code_id: code.id,
                   vp_token: vp_token,
                   presentation_submission: valid_presentation_submission()
                 },
                 ApplicationMock
               )
    end

    test "oid4vp - rejects a current public client absent from the code chain", %{
      code: base_code,
      vp_token: vp_token
    } do
      {:ok, wallet_did, _public_jwk} = Boruta.Did.Crypto.did_key(public_jwk_fixture())
      client = insert(:client, check_public_client_id: true)

      [code | _code_chain] =
        public_client_code_chain(
          client,
          wallet_did,
          "did:example:other",
          base_code.presentation_definition
        )

      assert_public_client_failure(
        code,
        vp_token,
        "Could not find client_id in code chain."
      )
    end

    test "oid4vp - ignores a revoked public client in the code chain", %{
      code: base_code,
      vp_token: vp_token
    } do
      {:ok, wallet_did, _public_jwk} = Boruta.Did.Crypto.did_key(public_jwk_fixture())
      client = insert(:client, check_public_client_id: true)

      [code, previous] =
        public_client_code_chain(
          client,
          wallet_did,
          wallet_did,
          base_code.presentation_definition
        )

      previous
      |> Ecto.Changeset.change(revoked_at: DateTime.utc_now())
      |> Repo.update!()

      assert_public_client_failure(
        code,
        vp_token,
        "Could not find client_id in code chain."
      )
    end

    test "oid4vp - does not verify against a revoked earlier DID", %{
      code: base_code,
      vp_token: vp_token
    } do
      {:ok, wallet_did, _public_jwk} = Boruta.Did.Crypto.did_key(public_jwk_fixture())
      client = insert(:client, check_public_client_id: true)

      [code, previous] =
        public_client_code_chain(
          client,
          "did:example:current",
          wallet_did,
          base_code.presentation_definition
        )

      previous
      |> Ecto.Changeset.change(revoked_at: DateTime.utc_now())
      |> Repo.update!()

      assert_public_client_failure(
        code,
        vp_token,
        "Could not verify given token in code chain."
      )
    end

    test "oid4vp - rejects a token unmatched by every active DID", %{
      code: base_code,
      vp_token: vp_token
    } do
      client = insert(:client, check_public_client_id: true)

      [code | _code_chain] =
        public_client_code_chain(
          client,
          "did:example:current",
          "did:example:previous",
          base_code.presentation_definition
        )

      assert_public_client_failure(
        code,
        vp_token,
        "Could not verify given token in code chain."
      )
    end
  end

  defp code_chain_with_policy(client, wallet_did, metadata_policy) do
    code_params = [
      type: "code",
      client: client,
      redirect_uri: "http://redirect.uri",
      state: "state",
      sub: wallet_did
    ]

    oldest = insert(:token, [{:value, SecureRandom.uuid()} | code_params])

    policy_code =
      insert(
        :token,
        [
          {:value, SecureRandom.uuid()},
          {:previous_code, oldest.value},
          {:metadata_policy, metadata_policy}
          | code_params
        ]
      )

    current =
      insert(
        :token,
        [{:previous_code, policy_code.value}, {:public_client_id, wallet_did} | code_params]
      )

    [current, policy_code, oldest]
  end

  defp public_client_code_chain(
         client,
         public_client_id,
         previous_subject,
         presentation_definition
       ) do
    previous =
      insert(:token,
        type: "code",
        client: client,
        sub: previous_subject,
        redirect_uri: "http://redirect.uri",
        state: "state"
      )

    current =
      insert(:token,
        type: "code",
        client: client,
        public_client_id: public_client_id,
        previous_code: previous.value,
        redirect_uri: "http://redirect.uri",
        state: "state",
        presentation_definition: presentation_definition
      )

    [current, previous]
  end

  defp valid_presentation_submission do
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
  end

  defp assert_public_client_failure(code, vp_token, description) do
    assert {:authentication_failure,
            %Boruta.Oauth.Error{
              status: :bad_request,
              error: :invalid_client,
              error_description: ^description,
              format: :query,
              redirect_uri: "http://redirect.uri",
              state: "state"
            }} =
             Openid.direct_post(
               %Plug.Conn{},
               %{
                 code_id: code.id,
                 vp_token: vp_token,
                 presentation_submission: valid_presentation_submission()
               },
               ApplicationMock
             )
  end

  defp configure_codes_adapter(adapter) do
    original_config = Application.get_env(:boruta, Boruta.Oauth, [])
    contexts = Keyword.get(original_config, :contexts, [])

    Application.put_env(
      :boruta,
      Boruta.Oauth,
      Keyword.put(original_config, :contexts, Keyword.put(contexts, :codes, adapter))
    )

    on_exit(fn -> Application.put_env(:boruta, Boruta.Oauth, original_config) end)
  end

  def public_key_fixture do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def public_jwk_fixture do
    public_key_fixture()
    |> JOSE.JWK.from_pem()
    |> JOSE.JWK.to_map()
    |> elem(1)
  end

  def did_jwk_fixture do
    "did:jwk:" <> (Jason.encode!(public_jwk_fixture()) |> Base.url_encode64(padding: false))
  end

  def private_key_fixture do
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVO\nf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa\n9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8Wd\nSq3dGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/\nU8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2t\npyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQABAoIBAG0dg/upL8k1IWiv\n8BNphrXIYLYQmiiBQTPJWZGvWIC2sl7i40yvCXjDjiRnZNK9HwgL94XtALCXYRFR\nJD41bRA3MO5A0HSPIWwJXwS10/cU56HVCNHjwKa6Rz/QiG2kNASMZEMzlvHtrjna\ndx36/sjI3HH8gh1BaTZyiuDE72SMkPbL838jfL1YY9uJ0u6hWFDbdn3sqPfJ6Cnz\n1cu0piT35nkilnIGCNYA0i3lyMeo4XrdXaAJdN9nnqbCi5ewQWqaHbrIIY5LTgzJ\nYlOr3IiecyokFxHCbULXle60u0KqXYgBHmlQJJr1Dj4c9AkQmefjC2jRMlhOrIzo\nIkIUeMECgYEA+MNLB+w6vv1ogqzM3M1OLt6bziWJCn+XkziuMrCiY9KeDD+S70+E\nhfbhM5RjCE3wxC/k59039laT973BmdMHxrDd2zSjOFmCIORv5yrD5oBHMaMZcwuQ\n45Xisi4aoQoOhyznSnjo/RjeQB7qEDzXFznLLNT79HzqyAtCWD3UIu8CgYEA2yik\n9FKl7HJEY94D2K6vNh1AHGnkwIQC72pXzlUrVuwQYngj6/Gkhw8ayFBApHfwVCXj\no9rDYPdNrrAs0Zz0JsiJp6bOCEKCrMYE16UiejUUAg/OZ5eg6+3m3/iWatkzLUuK\n1LIkVBJlEyY0uPuAaBF0V0VleNvfCGhVYOn46+ECgYAUD4OsduNh5YOZDiBTKgdF\nBlSgMiyz+QgbKjX6Bn6B+EkgibvqqonwV7FffHbkA40H9SjLfe52YhL6poXHRtpY\nroillcAX2jgBOQrBJJS5sNyM5y81NNiRUdP/NHKXS/1R71ATlF6NkoTRvOx5NL7P\ns6xryB0tYSl5ylamUQ4bZwKBgHF6FB9mA//wErVbKcayfIqajq2nrwh30kVBXQG7\nW9uAE+PIrWDoF/bOvWFnHHGMoOYRUFNxXKUCqDiBhFNs34aNY6lpV1kzhxIK3ksC\neF2qyhdfM9Kz0mEXJ+pkfw4INNWJPfNv4hueArPtnnMB1rUMBJ+DkU0JG+zwiPTL\ncVZBAoGBAM6kOsh5KGn3aI83g9ZO0TrKLXXFotxJt31Wu11ydj9K33/Qj3UXcxd4\nJPXr600F0DkLeUKBob6BALeHFWcrSz5FGLGRqdRxdv+L6g18WH5m2xEs7o6M6e5I\nIhyUC60ZewJ2M8rV4KgCJJdZE2kENlSgjU92IDVPT9Oetrc7hQJd\n-----END RSA PRIVATE KEY-----\n\n"
  end
end
