defmodule Boruta.OpenidTest.CredentialTest do
  use Boruta.DataCase, async: false

  defmodule FailingCredentials do
    @behaviour Boruta.Openid.Credentials

    @impl Boruta.Openid.Credentials
    def create_credential(_credential, _token), do: {:error, :storage_unavailable}

    @impl Boruta.Openid.Credentials
    def get_by(_params), do: nil
  end

  defmodule MissingCodes do
    def get_by(_params), do: nil
  end

  import Boruta.Factory
  import Plug.Conn
  import Mox

  alias Boruta.Config
  alias Boruta.Ecto.Client
  alias Boruta.Ecto.ClientStore
  alias Boruta.Ecto.Token
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Openid
  alias Boruta.Openid.ApplicationMock
  alias Boruta.Openid.CredentialResponse
  alias Boruta.Openid.DeferedCredentialResponse
  alias Boruta.Openid.VerifiableCredentials

  setup :verify_on_exit!

  describe "deliver verifiable credentials" do
    setup do
      :ok = ClientStore.invalidate_public()

      {:ok, client} =
        Repo.get_by(Client, public_client_id: Boruta.Config.issuer())
        |> Ecto.Changeset.change(%{check_public_client_id: false})
        |> Repo.update()

      :ok = ClientStore.invalidate(client)

      {:ok, public_client: client}
    end

    test "returns an error with no access token" do
      conn = %Plug.Conn{}

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_request,
                error_description: "Invalid bearer from Authorization header.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, %{}, ApplicationMock)
    end

    test "returns credential_failure with a bad authorization header" do
      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "not a bearer")

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_request,
                error_description: "Invalid bearer from Authorization header.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, %{}, ApplicationMock)
    end

    test "returns credential_failure with a bad access token" do
      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer bad_token")

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_access_token,
                error_description: "Given access token is invalid, revoked, or expired.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, %{}, ApplicationMock)
    end

    test "returns credential_failure with a malformed encrypted request" do
      %Token{value: access_token} = insert(:token)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_failure,
              %Error{
                status: :bad_request,
                error: :invalid_request,
                error_description: "Could not decrypt the given payload."
              }} =
               Openid.credential(
                 conn,
                 %{"encrypted_request" => "not-a-jwe"},
                 %{},
                 ApplicationMock
               )
    end

    test "returns an error with a valid bearer" do
      credential_params = %{}
      %Token{value: access_token} = insert(:token)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert Openid.credential(conn, credential_params, %{}, ApplicationMock) ==
               {:credential_failure,
                %Error{
                  status: :bad_request,
                  error: :invalid_request,
                  error_description:
                    "Request body validation failed. Required properties format, proof are missing at #."
                }}
    end

    test "returns an error with an access token without a previous code" do
      credential_params = %{
        "credential_identifier" => "identifier",
        "format" => "jwt_vc",
        "proof" => %{"proof_type" => "jwt", "jwt" => ""}
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok, %ResourceOwner{sub: sub}}
      end)

      %Token{value: access_token} = insert(:token, sub: sub)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert Openid.credential(conn, credential_params, %{}, ApplicationMock) ==
               {:credential_failure,
                %Error{
                  status: :bad_request,
                  error: :invalid_request,
                  error_description: "Code not found."
                }}
    end

    test "returns an error when the codes adapter cannot find the previous code" do
      configure_context(:codes, MissingCodes)

      credential_params = %{
        "credential_identifier" => "identifier",
        "format" => "jwt_vc",
        "proof" => %{"proof_type" => "jwt", "jwt" => ""}
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok, %ResourceOwner{sub: sub}}
      end)

      %Token{value: access_token} =
        insert(:token, sub: sub, previous_code: "missing-code")

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_failure,
              %Error{
                status: :bad_request,
                error: :invalid_request,
                error_description: "Previous code not found."
              }} = Openid.credential(conn, credential_params, %{}, ApplicationMock)
    end

    test "returns an error for a malformed proof from a public client", %{
      public_client: client
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

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok, %ResourceOwner{sub: sub}}
      end)

      code = insert(:token, type: "code", client: client)

      %Token{value: access_token} =
        insert(:token, client: client, sub: sub, previous_code: code.value)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_failure,
              %Error{
                status: :bad_request,
                error: :invalid_request,
                error_description: "VP token is invalid."
              }} =
               Openid.credential(
                 conn,
                 %{
                   "credential_identifier" => "identifier",
                   "format" => "jwt_vc",
                   "proof" => %{"proof_type" => "jwt", "jwt" => "not-a-jwt"}
                 },
                 %{},
                 ApplicationMock
               )
    end

    test "returns an error with an invalid types" do
      credential_params = %{
        "credential_identifier" => "bad type",
        "format" => "jwt_vc",
        "proof" => %{"proof_type" => "jwt", "jwt" => ""}
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok, %ResourceOwner{sub: sub}}
      end)

      %Token{value: access_token} =
        insert(:token, sub: sub, previous_code: insert(:token, type: "preauthorized_code").value)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert Openid.credential(conn, credential_params, %{}, ApplicationMock) ==
               {:credential_failure,
                %Error{
                  status: :bad_request,
                  error: :invalid_request,
                  error_description: "Credential not found."
                }}
    end

    test "returns a credential" do
      {_, public_jwk} = public_key_fixture() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{
            "aud" => Config.issuer(),
            "iat" => :os.system_time(:seconds)
          },
          signer
        )

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      credential_params = %{
        "format" => "jwt_vc",
        "proof" => proof,
        "credential_identifier" => "VerifiableCredential"
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok,
         %ResourceOwner{
           sub: sub,
           credential_configuration: %{
             "VerifiableCredential" => %{
               version: "13",
               format: "jwt_vc",
               time_to_live: 3600,
               claims: ["family_name"]
             }
           },
           extra_claims: %{
             "family_name" => "family_name"
           }
         }}
      end)

      %Token{value: access_token, client: client} =
        insert(:token,
          sub: sub,
          authorization_details: [%{"credential_identifiers" => ["VerifiableCredential"]}],
          previous_code: insert(:token, type: "preauthorized_code").value
        )

      encrypted_request =
        client.public_key
        |> JOSE.JWK.from_pem()
        |> JOSE.JWE.block_encrypt(Jason.encode!(credential_params), %{
          "alg" => "RSA-OAEP",
          "enc" => "A256GCM"
        })
        |> JOSE.JWE.compact()
        |> elem(1)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_created,
              %CredentialResponse{
                format: "jwt_vc",
                credential: credential
              }} =
               Openid.credential(
                 conn,
                 %{"encrypted_request" => encrypted_request},
                 %{},
                 ApplicationMock
               )

      # TODO validate credential body
      assert credential
    end

    @tag :skip
    test "returns an error with invalid code chain", %{public_client: client} do
      {_, public_jwk} = public_key_fixture() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{
            "aud" => Config.issuer(),
            "iat" => :os.system_time(:seconds)
          },
          signer
        )

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      credential_params = %{
        "format" => "jwt_vc",
        "proof" => proof,
        "credential_identifier" => "VerifiableCredential"
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok,
         %ResourceOwner{
           sub: sub,
           credential_configuration: %{
             "VerifiableCredential" => %{
               version: "13",
               format: "jwt_vc",
               time_to_live: 3600,
               claims: ["family_name"]
             }
           },
           extra_claims: %{
             "family_name" => "family_name"
           }
         }}
      end)

      invalid_code_chain = [
        insert(
          :token,
          [{:type, "code"}, {:previous_code, "invalid_code_2"}, {:value, "invalid_code_1"}]
        ),
        insert(
          :token,
          [{:type, "code"}, {:sub, "did:key:invalid"}, {:value, "invalid_code_2"}]
        )
      ]

      %Token{value: access_token} =
        insert(:token,
          client: client,
          sub: sub,
          authorization_details: [%{"credential_identifiers" => ["VerifiableCredential"]}],
          previous_code: List.first(invalid_code_chain).value
        )

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {
               :credential_failure,
               %Boruta.Oauth.Error{
                 error: :invalid_client,
                 error_description: "Could not verify given token in code chain.",
                 status: :bad_request
               }
             } = Openid.credential(conn, credential_params, %{}, ApplicationMock)
    end

    test "returns an error with invalid code chain (policy)", %{public_client: client} do
      wallet_did =
        "did:key:z4MXj1wBzi9jUstyQAVUF6ibbHUd3jozWgVWFNHUEd8WFtuQAcRojJDf97jQeR6nA5PXoYC3nb1BrjbYQrxRWinvz5tjtMxT4fFTtHkxjojdoSyEdRBgEupBfhz5axKi9WE5hLS4eiwGLuaQWUq48manvZjSHUi3azj8exMDx2XKjHSeB2BuNr9Bwse3ts9MctQrNtDg2LP1R7ZRdUWQuqLzZ87bQJgJZ7BWqA92dfMcgZ17ZysNZmSfUgXxFXhyb42N8wnG8wxdWprmJv9wBsEXjcCUiJhdTu8NGABQQ2QNhNYVuwfHgCCsZqxkmVXMN9kynQV2NCNkPkLxNP3VzSMw7FLjLFMsnyPXd4ph9yyYF3iDmVKtC"

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "kid" => wallet_did,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{
            "aud" => Config.issuer(),
            "iat" => :os.system_time(:seconds)
          },
          signer
        )

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      credential_params = %{
        "format" => "jwt_vc",
        "proof" => proof,
        "credential_identifier" => "VerifiableCredential"
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok,
         %ResourceOwner{
           sub: sub,
           credential_configuration: %{
             "VerifiableCredential" => %{
               version: "13",
               format: "jwt_vc",
               time_to_live: 3600,
               claims: ["family_name"]
             }
           },
           extra_claims: %{
             "family_name" => "family_name"
           }
         }}
      end)

      invalid_code_chain = [
        insert(
          :token,
          [{:type, "code"}, {:previous_code, "invalid_code_2"}, {:value, "invalid_code_1"}]
        ),
        insert(
          :token,
          [
            {:type, "code"},
            {:sub, "did:key:invalid"},
            {:value, "invalid_code_2"},
            {:metadata_policy, %{"client_id" => %{"one_of" => ["did:key:test"]}}}
          ]
        )
      ]

      %Token{value: access_token} =
        insert(:token,
          client: client,
          sub: sub,
          authorization_details: [%{"credential_identifiers" => ["VerifiableCredential"]}],
          previous_code: List.first(invalid_code_chain).value
        )

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {
               :credential_failure,
               %Boruta.Oauth.Error{
                 error: :unauthorized,
                 error_description: "Metadata policies check failed.",
                 status: :unauthorized
               }
             } = Openid.credential(conn, credential_params, %{}, ApplicationMock)
    end

    test "returns a credential with a public client", %{public_client: client} do
      wallet_did =
        "did:key:z4MXj1wBzi9jUstyQAVUF6ibbHUd3jozWgVWFNHUEd8WFtuQAcRojJDf97jQeR6nA5PXoYC3nb1BrjbYQrxRWinvz5tjtMxT4fFTtHkxjojdoSyEdRBgEupBfhz5axKi9WE5hLS4eiwGLuaQWUq48manvZjSHUi3azj8exMDx2XKjHSeB2BuNr9Bwse3ts9MctQrNtDg2LP1R7ZRdUWQuqLzZ87bQJgJZ7BWqA92dfMcgZ17ZysNZmSfUgXxFXhyb42N8wnG8wxdWprmJv9wBsEXjcCUiJhdTu8NGABQQ2QNhNYVuwfHgCCsZqxkmVXMN9kynQV2NCNkPkLxNP3VzSMw7FLjLFMsnyPXd4ph9yyYF3iDmVKtC"

      {_, public_jwk} = public_key_fixture() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{
            "aud" => Config.issuer(),
            "iat" => :os.system_time(:seconds)
          },
          signer
        )

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      credential_params = %{
        "format" => "jwt_vc",
        "proof" => proof,
        "credential_identifier" => "VerifiableCredential"
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok,
         %ResourceOwner{
           sub: sub,
           credential_configuration: %{
             "VerifiableCredential" => %{
               version: "13",
               format: "jwt_vc",
               time_to_live: 3600,
               claims: ["family_name"]
             }
           },
           extra_claims: %{
             "family_name" => "family_name"
           }
         }}
      end)

      valid_code_chain = [
        insert(
          :token,
          [{:type, "code"}, {:previous_code, "middle_code_2"}, {:value, "middle_code_1"}]
        ),
        insert(
          :token,
          [{:type, "code"}, {:sub, wallet_did}, {:value, "middle_code_2"}]
        )
      ]

      %Token{value: access_token} =
        insert(:token,
          client: client,
          sub: sub,
          authorization_details: [%{"credential_identifiers" => ["VerifiableCredential"]}],
          previous_code: List.first(valid_code_chain).value
        )

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_created,
              %CredentialResponse{
                format: "jwt_vc",
                credential: credential
              }} = Openid.credential(conn, credential_params, %{}, ApplicationMock)

      # TODO validate credential body
      assert credential
    end

    test "returns a credential after proof and metadata-policy public-client checks", %{
      public_client: client
    } do
      on_exit(fn ->
        ClientStore.invalidate(client)
        ClientStore.invalidate_public()
      end)

      {:ok, client} =
        client
        |> Ecto.Changeset.change(%{check_public_client_id: true})
        |> Repo.update()

      {_, public_jwk} = public_key_fixture() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()
      {:ok, wallet_did, _public_jwk} = Boruta.Did.Crypto.did_key(public_jwk)

      proof_client_id =
        "did:jwk:" <> (Jason.encode!(public_jwk) |> Base.url_encode64(padding: false))

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, jwt, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{"aud" => Config.issuer(), "iat" => :os.system_time(:seconds)},
          signer
        )

      credential_params = %{
        "format" => "jwt_vc",
        "proof" => %{"proof_type" => "jwt", "jwt" => jwt},
        "credential_identifier" => "VerifiableCredential"
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok,
         %ResourceOwner{
           sub: sub,
           credential_configuration: %{
             "VerifiableCredential" => %{
               version: "13",
               format: "jwt_vc",
               time_to_live: 3600,
               claims: ["family_name"]
             }
           },
           extra_claims: %{"family_name" => "family_name"}
         }}
      end)

      oldest =
        insert(:token,
          type: "code",
          client: client,
          sub: wallet_did,
          metadata_policy: %{"client_id" => %{"one_of" => [proof_client_id]}}
        )

      policy_code =
        insert(:token,
          type: "code",
          client: client,
          sub: wallet_did,
          previous_code: oldest.value
        )

      current =
        insert(:token,
          type: "code",
          client: client,
          sub: wallet_did,
          previous_code: policy_code.value
        )

      %Token{value: access_token} =
        insert(:token,
          client: client,
          sub: sub,
          authorization_details: [%{"credential_identifiers" => ["VerifiableCredential"]}],
          previous_code: current.value
        )

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_created, %CredentialResponse{credential: credential}} =
               Openid.credential(conn, credential_params, %{}, ApplicationMock)

      assert credential
    end
  end

  describe "deliver defered verifiable credentials" do
    test "returns an error when fetching without an access token" do
      assert {:credential_failure,
              %Error{
                status: :bad_request,
                error: :invalid_request,
                error_description: "Invalid bearer from Authorization header."
              }} = Openid.defered_credential(%Plug.Conn{}, ApplicationMock)
    end

    test "returns an error when fetching with an invalid access token" do
      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer bad_token")

      assert {:credential_failure,
              %Error{
                status: :bad_request,
                error: :invalid_access_token,
                error_description: "Given access token is invalid, revoked, or expired."
              }} = Openid.defered_credential(conn, ApplicationMock)
    end

    test "returns an error when no credential matches the acceptance token" do
      %Token{value: access_token} = insert(:token)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_failure,
              %Error{
                status: :bad_request,
                error: :invalid_request,
                error_description: "Credential not found."
              }} = Openid.defered_credential(conn, ApplicationMock)
    end

    test "returns an error with no access token" do
      conn = %Plug.Conn{}

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_request,
                error_description: "Invalid bearer from Authorization header.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, %{}, ApplicationMock)
    end

    test "returns credential_failure with a bad authorization header" do
      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "not a bearer")

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_request,
                error_description: "Invalid bearer from Authorization header.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, %{}, ApplicationMock)
    end

    test "returns credential_failure with a bad access token" do
      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer bad_token")

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_access_token,
                error_description: "Given access token is invalid, revoked, or expired.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, %{}, ApplicationMock)
    end

    test "returns an error with a valid bearer" do
      credential_params = %{}
      %Token{value: access_token} = insert(:token)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert Openid.credential(conn, credential_params, %{}, ApplicationMock) ==
               {:credential_failure,
                %Error{
                  status: :bad_request,
                  error: :invalid_request,
                  error_description:
                    "Request body validation failed. Required properties format, proof are missing at #."
                }}
    end

    test "returns an error with an invalid types" do
      credential_params = %{
        "credential_identifier" => "bad type",
        "format" => "jwt_vc",
        "proof" => %{"proof_type" => "jwt", "jwt" => ""}
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok, %ResourceOwner{sub: sub}}
      end)

      %Token{value: access_token} =
        insert(:token, sub: sub, previous_code: insert(:token, type: "preauthorized_code").value)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert Openid.credential(conn, credential_params, %{}, ApplicationMock) ==
               {:credential_failure,
                %Error{
                  status: :bad_request,
                  error: :invalid_request,
                  error_description: "Credential not found."
                }}
    end

    test "returns a defered credential response" do
      {_, public_jwk} = public_key_fixture() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{
            "aud" => Config.issuer(),
            "iat" => :os.system_time(:seconds)
          },
          signer
        )

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      credential_params = %{
        "format" => "jwt_vc",
        "proof" => proof,
        "credential_identifier" => "VerifiableCredential"
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok,
         %ResourceOwner{
           sub: sub,
           credential_configuration: %{
             "VerifiableCredential" => %{
               defered: true,
               version: "13",
               format: "jwt_vc",
               time_to_live: 3600,
               claims: ["family_name"]
             }
           },
           extra_claims: %{
             "family_name" => "family_name"
           }
         }}
      end)

      %Token{value: access_token} =
        insert(:token,
          sub: sub,
          authorization_details: [%{"credential_identifiers" => ["VerifiableCredential"]}],
          previous_code: insert(:token, type: "preauthorized_code").value
        )

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_created,
              %DeferedCredentialResponse{
                acceptance_token: acceptance_token
              }} = Openid.credential(conn, credential_params, %{}, ApplicationMock)

      assert acceptance_token
    end

    test "returns an internal error when a defered credential cannot be persisted" do
      configure_context(:credentials, FailingCredentials)

      {_, public_jwk} = public_key_fixture() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, jwt, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{"aud" => Config.issuer(), "iat" => :os.system_time(:seconds)},
          signer
        )

      credential_params = %{
        "format" => "jwt_vc",
        "proof" => %{"proof_type" => "jwt", "jwt" => jwt},
        "credential_identifier" => "VerifiableCredential"
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok,
         %ResourceOwner{
           sub: sub,
           credential_configuration: %{
             "VerifiableCredential" => %{
               defered: true,
               version: "13",
               format: "jwt_vc",
               time_to_live: 3600,
               claims: ["family_name"]
             }
           },
           extra_claims: %{"family_name" => "family_name"}
         }}
      end)

      %Token{value: access_token} =
        insert(:token,
          sub: sub,
          authorization_details: [%{"credential_identifiers" => ["VerifiableCredential"]}],
          previous_code: insert(:token, type: "preauthorized_code").value
        )

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_failure,
              %Error{
                status: :internal_server_error,
                error: :unknown_error,
                error_description: ":storage_unavailable"
              }} = Openid.credential(conn, credential_params, %{}, ApplicationMock)
    end

    test "gets a defered credential" do
      {_, public_jwk} = public_key_fixture() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{
            "aud" => Config.issuer(),
            "iat" => :os.system_time(:seconds)
          },
          signer
        )

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      credential_params = %{
        "format" => "jwt_vc",
        "proof" => proof,
        "credential_identifier" => "VerifiableCredential"
      }

      sub = SecureRandom.uuid()

      expect(Boruta.Support.ResourceOwners, :get_by, fn sub: ^sub, scope: _scope ->
        {:ok,
         %ResourceOwner{
           sub: sub,
           credential_configuration: %{
             "VerifiableCredential" => %{
               defered: true,
               version: "13",
               format: "jwt_vc",
               time_to_live: 3600,
               claims: ["family_name"]
             }
           },
           extra_claims: %{
             "family_name" => "family_name"
           }
         }}
      end)

      %Token{value: access_token} =
        insert(:token,
          sub: sub,
          authorization_details: [%{"credential_identifiers" => ["VerifiableCredential"]}],
          previous_code: insert(:token, type: "preauthorized_code").value
        )

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert {:credential_created,
              %DeferedCredentialResponse{
                acceptance_token: acceptance_token
              }} = Openid.credential(conn, credential_params, %{}, ApplicationMock)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{acceptance_token}")

      assert {:credential_created,
              %CredentialResponse{
                credential: credential
              }} = Openid.defered_credential(conn, ApplicationMock)

      # TODO validate credential body
      assert credential
    end
  end

  defp configure_context(context, adapter) do
    original_config = Application.get_env(:boruta, Boruta.Oauth, [])
    contexts = Keyword.get(original_config, :contexts, [])

    Application.put_env(
      :boruta,
      Boruta.Oauth,
      Keyword.put(original_config, :contexts, Keyword.put(contexts, context, adapter))
    )

    on_exit(fn -> Application.put_env(:boruta, Boruta.Oauth, original_config) end)
  end

  def public_key_fixture do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def private_key_fixture do
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVO\nf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa\n9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8Wd\nSq3dGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/\nU8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2t\npyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQABAoIBAG0dg/upL8k1IWiv\n8BNphrXIYLYQmiiBQTPJWZGvWIC2sl7i40yvCXjDjiRnZNK9HwgL94XtALCXYRFR\nJD41bRA3MO5A0HSPIWwJXwS10/cU56HVCNHjwKa6Rz/QiG2kNASMZEMzlvHtrjna\ndx36/sjI3HH8gh1BaTZyiuDE72SMkPbL838jfL1YY9uJ0u6hWFDbdn3sqPfJ6Cnz\n1cu0piT35nkilnIGCNYA0i3lyMeo4XrdXaAJdN9nnqbCi5ewQWqaHbrIIY5LTgzJ\nYlOr3IiecyokFxHCbULXle60u0KqXYgBHmlQJJr1Dj4c9AkQmefjC2jRMlhOrIzo\nIkIUeMECgYEA+MNLB+w6vv1ogqzM3M1OLt6bziWJCn+XkziuMrCiY9KeDD+S70+E\nhfbhM5RjCE3wxC/k59039laT973BmdMHxrDd2zSjOFmCIORv5yrD5oBHMaMZcwuQ\n45Xisi4aoQoOhyznSnjo/RjeQB7qEDzXFznLLNT79HzqyAtCWD3UIu8CgYEA2yik\n9FKl7HJEY94D2K6vNh1AHGnkwIQC72pXzlUrVuwQYngj6/Gkhw8ayFBApHfwVCXj\no9rDYPdNrrAs0Zz0JsiJp6bOCEKCrMYE16UiejUUAg/OZ5eg6+3m3/iWatkzLUuK\n1LIkVBJlEyY0uPuAaBF0V0VleNvfCGhVYOn46+ECgYAUD4OsduNh5YOZDiBTKgdF\nBlSgMiyz+QgbKjX6Bn6B+EkgibvqqonwV7FffHbkA40H9SjLfe52YhL6poXHRtpY\nroillcAX2jgBOQrBJJS5sNyM5y81NNiRUdP/NHKXS/1R71ATlF6NkoTRvOx5NL7P\ns6xryB0tYSl5ylamUQ4bZwKBgHF6FB9mA//wErVbKcayfIqajq2nrwh30kVBXQG7\nW9uAE+PIrWDoF/bOvWFnHHGMoOYRUFNxXKUCqDiBhFNs34aNY6lpV1kzhxIK3ksC\neF2qyhdfM9Kz0mEXJ+pkfw4INNWJPfNv4hueArPtnnMB1rUMBJ+DkU0JG+zwiPTL\ncVZBAoGBAM6kOsh5KGn3aI83g9ZO0TrKLXXFotxJt31Wu11ydj9K33/Qj3UXcxd4\nJPXr600F0DkLeUKBob6BALeHFWcrSz5FGLGRqdRxdv+L6g18WH5m2xEs7o6M6e5I\nIhyUC60ZewJ2M8rV4KgCJJdZE2kENlSgjU92IDVPT9Oetrc7hQJd\n-----END RSA PRIVATE KEY-----\n\n"
  end
end
