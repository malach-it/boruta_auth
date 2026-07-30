defmodule Boruta.Openid.VerifiableCredentialsTest do
  use Boruta.DataCase, async: true

  defmodule FailingSignatures do
    @behaviour Boruta.Openid.Signatures

    @impl Boruta.Openid.Signatures
    def verifiable_credential_sign(_payload, _client, _format),
      do: {:error, "signing failed"}
  end

  import Boruta.Factory
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  alias Boruta.Config
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Openid.VerifiableCredentials

  describe "issue_verifiable_credential/4" do
    setup do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk_fixture(),
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

      resource_owner = %ResourceOwner{
        sub: SecureRandom.uuid(),
        extra_claims: %{
          "firstname" => "firstname"
        },
        credential_configuration: %{
          "VerifiableCredential" => %{
            version: "13",
            time_to_live: 3600,
            format: "jwt_vc",
            claims: [
              %{
                "name" => "firstname",
                "label" => "firstname",
                "pointer" => "firstname",
                "expiration" => "3600"
              }
            ]
          }
        }
      }

      credential_params = %{
        "credential_identifier" => "VerifiableCredential",
        "format" => "jwt_vc",
        "proof" => proof
      }

      {:ok,
       proof: proof,
       resource_owner: resource_owner,
       credential_params: credential_params,
       signer: signer}
    end

    test "verifies proof - proof format", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               Map.put(credential_params, "proof", %{}),
               insert(:token) |> to_oauth_schema(),
               %{}
             ) ==
               {:error,
                "Proof validation failed. Required properties proof_type, jwt are missing at #."}
    end

    test "verifies proof - header claims", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      signer = Joken.Signer.create("HS256", "secret", %{"typ" => "unknown"})

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               Map.put(credential_params, "proof", proof),
               insert(:token) |> to_oauth_schema(),
               %{}
             ) ==
               {:error,
                "Proof JWT must be asymetrically signed, Proof JWT must have `openid4vci-proof+jwt` or `JWT` typ header, No proof key material found in JWT headers."}
    end

    test "verifies proof - the algorithm is asymetric", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      signer =
        Joken.Signer.create("HS256", "secret", %{
          "jwk" => public_jwk_fixture(),
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               Map.put(credential_params, "proof", proof),
               insert(:token) |> to_oauth_schema(),
               %{}
             ) == {:error, "Proof JWT must be asymetrically signed."}
    end

    test "verifies proof - typ header", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "typ" => "unknown",
          "jwk" => public_jwk_fixture()
        })

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               Map.put(credential_params, "proof", proof),
               insert(:token) |> to_oauth_schema(),
               %{}
             ) == {:error, "Proof JWT must have `openid4vci-proof+jwt` or `JWT` typ header."}
    end

    test "verifies proof - must have proof material", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               Map.put(credential_params, "proof", proof),
               insert(:token) |> to_oauth_schema(),
               %{}
             ) == {:error, "No proof key material found in JWT headers."}
    end

    test "prefers jwk header over kid when validating proof signature" do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk_fixture(),
          "kid" => "did:example:unknown",
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

      assert {:ok, jwk, %{"aud" => _aud, "iat" => _iat}} =
               VerifiableCredentials.validate_signature(token)

      assert jwk == public_jwk_fixture()
    end

    test "issues a credential from a proof with a did:key header", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      {:ok, did, _public_jwk} = Boruta.Did.Crypto.did_key(public_jwk_fixture())

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "kid" => did <> "#key",
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, jwt, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{
            "aud" => Config.issuer(),
            "iat" => :os.system_time(:seconds)
          },
          signer
        )

      credential_params =
        Map.put(credential_params, "proof", %{"proof_type" => "jwt", "jwt" => jwt})

      assert {:ok, %{format: "jwt_vc", credential: credential}} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 insert(:token) |> to_oauth_schema(),
                 %{}
               )

      assert credential
    end

    test "verifies proof - must have required claims", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "typ" => "openid4vci-proof+jwt",
          "jwk" => public_jwk_fixture()
        })

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               Map.put(credential_params, "proof", proof),
               insert(:token) |> to_oauth_schema(),
               %{}
             ) ==
               {:error,
                "Proof does not contain valid JWT claims, `aud` and `iat` claims are required."}
    end

    test "issues jwt_vc credential", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      assert {:ok,
              %{
                credential: credential,
                format: "jwt_vc"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 insert(:token) |> to_oauth_schema(),
                 %{}
               )

      # TODO validate credential body
      assert credential
    end

    test "issues credential selected by configuration scopes", %{
      resource_owner: %ResourceOwner{} = resource_owner,
      credential_params: credential_params
    } do
      jwk =
        private_key_fixture()
        |> JOSE.JWK.from_pem()
        |> JOSE.JWK.to_public()
        |> JOSE.JWK.to_map()
        |> elem(1)

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, jwt, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{
            "aud" => Config.issuer(),
            "iat" => :os.system_time(:seconds)
          },
          signer
        )

      resource_owner = %ResourceOwner{
        resource_owner
        | credential_configuration: %{
            "VerifiableCredential" =>
              Map.put(
                resource_owner.credential_configuration["VerifiableCredential"],
                :scopes,
                ["credential:read"]
              )
          }
      }

      credential_params =
        credential_params
        |> Map.put("proof", %{"proof_type" => "jwt", "jwt" => jwt})

      token = insert(:token, scope: "credential:read") |> to_oauth_schema()

      assert {:ok,
              %{
                credential: credential,
                format: "jwt_vc"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 token,
                 %{}
               )

      assert credential
    end

    test "issues credential selected by configuration scopes from code chain", %{
      resource_owner: %ResourceOwner{} = resource_owner,
      credential_params: credential_params
    } do
      jwk =
        private_key_fixture()
        |> JOSE.JWK.from_pem()
        |> JOSE.JWK.to_public()
        |> JOSE.JWK.to_map()
        |> elem(1)

      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, jwt, _claims} =
        VerifiableCredentials.Token.generate_and_sign(
          %{
            "aud" => Config.issuer(),
            "iat" => :os.system_time(:seconds)
          },
          signer
        )

      resource_owner = %ResourceOwner{
        resource_owner
        | credential_configuration: %{
            "VerifiableCredential" =>
              Map.put(
                resource_owner.credential_configuration["VerifiableCredential"],
                :scopes,
                ["credential:read"]
              )
          }
      }

      credential_params =
        credential_params
        |> Map.put("proof", %{"proof_type" => "jwt", "jwt" => jwt})

      token = insert(:token, scope: "other:scope") |> to_oauth_schema()
      code_chain = [insert(:token, type: "code", scope: "credential:read") |> to_oauth_schema()]

      assert {:ok,
              %{
                credential: credential,
                format: "jwt_vc"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 token,
                 %{},
                 code_chain
               )

      assert credential
    end

    test "returns an error when configuration scope is not authorized", %{
      resource_owner: %ResourceOwner{} = resource_owner,
      credential_params: credential_params
    } do
      resource_owner = %ResourceOwner{
        resource_owner
        | credential_configuration: %{
            "VerifiableCredential" =>
              Map.put(
                resource_owner.credential_configuration["VerifiableCredential"],
                :scopes,
                ["other:scope"]
              )
          }
      }

      token = insert(:token, scope: "credential:read") |> to_oauth_schema()

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_params,
               token,
               %{}
             ) == {:error, "Credential scope is not authorized."}
    end

    test "issues jwt_vc credential with nested claims", %{
      credential_params: credential_params
    } do
      resource_owner = %ResourceOwner{
        sub: SecureRandom.uuid(),
        extra_claims: %{
          "firstname" => "firstname",
          "lastname" => "lastname"
        },
        credential_configuration: %{
          "VerifiableCredential" => %{
            version: "13",
            time_to_live: 3600,
            format: "jwt_vc",
            claims: [
              %{
                "name" => "nested",
                "claims" => [
                  %{
                    "name" => "fullname",
                    "expiration" => "3600",
                    "items" => [
                      %{
                        "name" => "firstname",
                        "label" => "firstname",
                        "pointer" => "firstname",
                        "expiration" => "3600"
                      },
                      %{
                        "name" => "lastname",
                        "label" => "lastname",
                        "pointer" => "lastname",
                        "expiration" => "3600"
                      }
                    ]
                  },
                  %{
                    "name" => "firstname",
                    "label" => "firstname",
                    "pointer" => "firstname",
                    "expiration" => "3600"
                  },
                  %{
                    "name" => "twice",
                    "claims" => [
                      %{
                        "name" => "lastname",
                        "label" => "lastname",
                        "pointer" => "lastname",
                        "expiration" => "3600"
                      }
                    ]
                  }
                ]
              }
            ]
          }
        }
      }

      assert {:ok,
              %{
                credential: credential,
                format: "jwt_vc"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 insert(:token) |> to_oauth_schema(),
                 %{}
               )

      assert credential

      assert {:ok,
              %{
                "credentialSubject" => %{
                  "VerifiableCredential" => %{
                    "nested" => %{
                      "fullname" => [%{"firstname" => "firstname"}, %{"lastname" => "lastname"}],
                      "firstname" => "firstname",
                      "twice" => %{"lastname" => "lastname"}
                    }
                  }
                }
              }} = Joken.peek_claims(credential)
    end

    test "issues jwt_vc_json credential", %{
      credential_params: credential_params
    } do
      resource_owner = %ResourceOwner{
        sub: SecureRandom.uuid(),
        extra_claims: %{
          "firstname" => "firstname"
        },
        credential_configuration: %{
          "VerifiableCredential" => %{
            version: "13",
            time_to_live: 3600,
            format: "jwt_vc_json",
            claims: ["firstname"]
          }
        }
      }

      assert {:ok,
              %{
                credential: credential,
                format: "jwt_vc_json"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 insert(:token) |> to_oauth_schema(),
                 %{}
               )

      # TODO validate credential body
      assert credential
    end

    test "issues jwt_vc_json credential with nested claims", %{
      credential_params: credential_params
    } do
      resource_owner = %ResourceOwner{
        sub: SecureRandom.uuid(),
        extra_claims: %{
          "firstname" => "firstname",
          "lastname" => "lastname"
        },
        credential_configuration: %{
          "VerifiableCredential" => %{
            version: "13",
            time_to_live: 3600,
            format: "jwt_vc_json",
            claims: [
              %{
                "name" => "nested",
                "claims" => [
                  %{
                    "name" => "fullname",
                    "expiration" => "3600",
                    "items" => [
                      %{
                        "name" => "firstname",
                        "label" => "firstname",
                        "pointer" => "firstname",
                        "expiration" => "3600"
                      },
                      %{
                        "name" => "lastname",
                        "label" => "lastname",
                        "pointer" => "lastname",
                        "expiration" => "3600"
                      }
                    ]
                  },
                  %{
                    "name" => "firstname",
                    "label" => "firstname",
                    "pointer" => "firstname",
                    "expiration" => "3600"
                  },
                  %{
                    "name" => "twice",
                    "claims" => [
                      %{
                        "name" => "lastname",
                        "label" => "lastname",
                        "pointer" => "lastname",
                        "expiration" => "3600"
                      }
                    ]
                  }
                ]
              }
            ]
          }
        }
      }

      assert {:ok,
              %{
                credential: credential,
                format: "jwt_vc_json"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 insert(:token) |> to_oauth_schema(),
                 %{}
               )

      assert credential

      assert {:ok,
              %{
                "vc" => %{
                  "credentialSubject" => %{
                    "VerifiableCredential" => %{
                      "nested" => %{
                        "fullname" => [%{"firstname" => "firstname"}, %{"lastname" => "lastname"}],
                        "firstname" => "firstname",
                        "twice" => %{"lastname" => "lastname"}
                      }
                    }
                  }
                }
              }} = Joken.peek_claims(credential)
    end

    test "issues vc+sd-jwt credential", %{
      credential_params: credential_params
    } do
      resource_owner = %ResourceOwner{
        sub: SecureRandom.uuid(),
        extra_claims: %{
          "firstname" => "firstname"
        },
        credential_configuration: %{
          "VerifiableCredential" => %{
            version: "13",
            format: "vc+sd-jwt",
            claims: ["firstname"],
            time_to_live: 60
          }
        }
      }

      assert {:ok,
              %{
                credential: credential,
                format: "vc+sd-jwt"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 insert(:token) |> to_oauth_schema(),
                 %{}
               )

      # TODO validate credential body
      assert credential
    end

    test "issues vc+sd-jwt credential with nested claims", %{
      credential_params: credential_params
    } do
      resource_owner = %ResourceOwner{
        sub: SecureRandom.uuid(),
        extra_claims: %{
          "firstname" => "firstname",
          "lastname" => "lastname"
        },
        credential_configuration: %{
          "VerifiableCredential" => %{
            version: "13",
            format: "vc+sd-jwt",
            claims: [
              %{
                "name" => "nested",
                "claims" => [
                  %{
                    "name" => "fullname",
                    "expiration" => "3600",
                    "items" => [
                      %{
                        "name" => "firstname",
                        "label" => "firstname",
                        "pointer" => "firstname",
                        "expiration" => "3600"
                      },
                      %{
                        "name" => "lastname",
                        "label" => "lastname",
                        "pointer" => "lastname",
                        "expiration" => "3600"
                      }
                    ]
                  },
                  %{
                    "name" => "firstname",
                    "label" => "firstname",
                    "pointer" => "firstname",
                    "expiration" => "3600"
                  },
                  %{
                    "name" => "twice",
                    "claims" => [
                      %{
                        "name" => "lastname",
                        "label" => "lastname",
                        "pointer" => "lastname",
                        "expiration" => "3600"
                      }
                    ]
                  }
                ]
              }
            ],
            time_to_live: 60
          }
        }
      }

      assert {:ok,
              %{
                credential: credential,
                format: "vc+sd-jwt"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 insert(:token) |> to_oauth_schema(),
                 %{}
               )

      # TODO validate credential body
      assert credential
      [_credential | claims] = String.split(credential, "~") |> Enum.reject(&(&1 == ""))

      assert [
               [_salt1, "nested.fullname.0.firstname", "firstname"],
               [_salt2, "nested.fullname.1.lastname", "lastname"],
               [_salt3, "nested.firstname", "firstname"],
               [_salt4, "nested.twice.lastname", "lastname"]
             ] =
               Enum.map(claims, &Base.url_decode64!(&1, padding: false))
               |> Enum.map(&Jason.decode!/1)
    end

    test "issues vc+sd-jwt credential - valid", %{
      credential_params: credential_params
    } do
      resource_owner = %ResourceOwner{
        sub: SecureRandom.uuid(),
        extra_claims: %{
          "firstname" => %{
            "value" => "firstname",
            "status" => "suspended"
          },
          "lastname" => %{
            "value" => "lastname",
            "status" => "valid"
          }
        },
        credential_configuration: %{
          "VerifiableCredential" => %{
            version: "13",
            format: "vc+sd-jwt",
            claims: [
              %{
                "name" => "firstname",
                "label" => "firstname",
                "pointer" => "firstname",
                "expiration" => "3600"
              },
              %{
                "name" => "lastname",
                "label" => "lastname",
                "pointer" => "lastname",
                "expiration" => "3600"
              }
            ],
            time_to_live: 60
          }
        }
      }

      token = insert(:token) |> to_oauth_schema()

      assert {:ok,
              %{
                credential: credential,
                format: "vc+sd-jwt"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 token,
                 %{}
               )

      # TODO validate credential body
      assert credential
    end

    test "issues vc+sd-jwt credential - suspended", %{
      credential_params: credential_params
    } do
      resource_owner = %ResourceOwner{
        sub: SecureRandom.uuid(),
        extra_claims: %{
          "firstname" => %{
            "value" => "firstname",
            "status" => "suspended"
          }
        },
        credential_configuration: %{
          "VerifiableCredential" => %{
            version: "13",
            format: "vc+sd-jwt",
            claims: [
              %{
                "name" => "firstname",
                "label" => "firstname",
                "pointer" => "firstname",
                "expiration" => "3600"
              }
            ],
            time_to_live: 60
          }
        }
      }

      token = insert(:token) |> to_oauth_schema()

      assert {:ok,
              %{
                credential: credential,
                format: "vc+sd-jwt"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 token,
                 %{}
               )

      # TODO validate credential body
      assert credential
    end

    test "issues vc+sd-jwt credential - revoked", %{
      credential_params: credential_params
    } do
      resource_owner = %ResourceOwner{
        sub: SecureRandom.uuid(),
        extra_claims: %{
          "firstname" => %{
            "value" => "firstname",
            "status" => "revoked"
          }
        },
        credential_configuration: %{
          "VerifiableCredential" => %{
            version: "13",
            format: "vc+sd-jwt",
            claims: [
              %{
                "name" => "firstname",
                "label" => "firstname",
                "pointer" => "firstname",
                "expiration" => "3600"
              }
            ],
            time_to_live: 60
          }
        }
      }

      token = insert(:token) |> to_oauth_schema()

      assert {:ok,
              %{
                credential: credential,
                format: "vc+sd-jwt"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 token,
                 %{}
               )

      # TODO validate credential body
      assert credential
    end

    test "issues vc+sd-jwt credential - expired", %{
      credential_params: credential_params
    } do
      resource_owner = %ResourceOwner{
        sub: SecureRandom.uuid(),
        extra_claims: %{
          "firstname" => %{
            "value" => "firstname",
            "status" => "valid"
          }
        },
        credential_configuration: %{
          "VerifiableCredential" => %{
            version: "13",
            format: "vc+sd-jwt",
            claims: [
              %{
                "name" => "firstname",
                "label" => "firstname",
                "pointer" => "firstname",
                "expiration" => "1"
              }
            ],
            time_to_live: 60
          }
        }
      }

      token = insert(:token) |> to_oauth_schema()

      assert {:ok,
              %{
                credential: credential,
                format: "vc+sd-jwt"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 token,
                 %{}
               )

      :timer.sleep(1000)
      # TODO validate credential body
      assert credential

      suspended_salt_key =
        String.split(credential, "~")
        |> Enum.at(1)
        |> Base.url_decode64!(padding: false)
        |> Jason.decode!()
        |> List.first()
        |> String.split("~")
        |> List.last()

      refute suspended_salt_key ==
               VerifiableCredentials.Hotp.generate_hotp(
                 token.client.private_key,
                 div(:os.system_time(:seconds), 3600) + 33
               )

      refute suspended_salt_key ==
               VerifiableCredentials.Hotp.generate_hotp(
                 token.client.private_key,
                 div(:os.system_time(:seconds), 3600) + 44
               )

      refute suspended_salt_key ==
               VerifiableCredentials.Hotp.generate_hotp(
                 token.client.private_key,
                 div(:os.system_time(:seconds), 3600) + 55
               )
    end

    test "uses the default credential configuration for DID resource owners", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      default_configuration = resource_owner.credential_configuration
      resource_owner = %{resource_owner | sub: "did:example:resource-owner"}

      assert {:ok, %{format: "jwt_vc", credential: credential}} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 insert(:token) |> to_oauth_schema(),
                 default_configuration
               )

      assert credential
    end

    test "selects a version 11 credential by types", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      configuration =
        resource_owner.credential_configuration["VerifiableCredential"]
        |> Map.merge(%{version: "11", types: ["VerifiableCredential"]})

      resource_owner = %{
        resource_owner
        | credential_configuration: %{"LegacyCredential" => configuration}
      }

      credential_params =
        credential_params
        |> Map.delete("credential_identifier")
        |> Map.put("types", ["VerifiableCredential"])

      assert {:ok, %{format: "jwt_vc", credential: credential}} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 insert(:token) |> to_oauth_schema(),
                 %{}
               )

      assert credential
    end

    test "selects a version 13 credential from the token scope", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      credential_params = Map.put(credential_params, "credential_identifier", "other")
      token = insert(:token, scope: "VerifiableCredential") |> to_oauth_schema()

      assert {:ok, %{format: "jwt_vc", credential: credential}} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 token,
                 %{}
               )

      assert credential
    end

    test "ignores credential configurations with unknown versions", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      configuration =
        resource_owner.credential_configuration["VerifiableCredential"]
        |> Map.put(:version, "unknown")

      resource_owner = %{
        resource_owner
        | credential_configuration: %{"VerifiableCredential" => configuration}
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_params,
               insert(:token) |> to_oauth_schema(),
               %{}
             ) == {:error, "Credential not found."}
    end

    test "rejects a malformed proof JWT", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      credential_params =
        Map.put(credential_params, "proof", %{
          "proof_type" => "jwt",
          "jwt" => "not-a-jwt"
        })

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_params,
               insert(:token) |> to_oauth_schema(),
               %{}
             ) ==
               {:error, "Proof does not contain valid JWT headers, `alg` and `typ` are required."}
    end

    test "rejects unsupported credential formats", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      configuration =
        resource_owner.credential_configuration["VerifiableCredential"]
        |> Map.put(:format, "unsupported")

      resource_owner = %{
        resource_owner
        | credential_configuration: %{"VerifiableCredential" => configuration}
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_params,
               insert(:token) |> to_oauth_schema(),
               %{}
             ) == {:error, "Unkown format."}
    end

    test "propagates signing failures for each supported format", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      token = token_with_signatures_adapter(FailingSignatures)

      for format <- ["jwt_vc", "jwt_vc_json", "vc+sd-jwt"] do
        configuration =
          resource_owner.credential_configuration["VerifiableCredential"]
          |> Map.put(:format, format)

        resource_owner = %{
          resource_owner
          | credential_configuration: %{"VerifiableCredential" => configuration}
        }

        assert VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 token,
                 %{}
               ) == {:error, "signing failed"}
      end
    end
  end

  describe "validate_authorization_details/1" do
    test "accepts valid credential authorization details" do
      authorization_details =
        Jason.encode!([
          %{
            "type" => "openid_credential",
            "format" => "jwt_vc",
            "credential_definition" => %{
              "type" => ["VerifiableCredential"]
            }
          }
        ])

      assert VerifiableCredentials.validate_authorization_details(authorization_details) == :ok
    end

    test "rejects authorization details that do not match the schema" do
      assert {:error, reason} =
               VerifiableCredentials.validate_authorization_details(
                 Jason.encode!([%{"type" => "openid_credential"}])
               )

      assert reason =~ "authorization_details validation failed."
      assert reason =~ "Required property format is missing"
    end

    test "rejects malformed authorization details JSON" do
      assert {:error, reason} =
               VerifiableCredentials.validate_authorization_details("not-json")

      assert reason =~ "authorization_details validation failed."
      assert reason =~ "Jason.DecodeError"
    end
  end

  describe "validate_signature/1" do
    test "rejects malformed and non-string proofs" do
      assert {:error, _reason} = VerifiableCredentials.validate_signature("not-a-jwt")

      assert VerifiableCredentials.validate_signature(nil) ==
               {:error, "Proof does not contain a valid JWT."}
    end

    test "rejects a proof whose embedded key does not match its signature" do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" =>
            JOSE.JWK.generate_key({:rsa, 2048})
            |> JOSE.JWK.to_public()
            |> JOSE.JWK.to_map()
            |> elem(1)
        })

      {:ok, jwt, _claims} =
        VerifiableCredentials.Token.generate_and_sign(%{"aud" => "test", "iat" => 1}, signer)

      assert VerifiableCredentials.validate_signature(jwt) ==
               {:error, "Bad proof signature"}
    end
  end

  describe "Status.generate_status/3" do
    setup do
      secret = "secret"
      expiration = 10
      now = :os.system_time(:seconds)

      revoked =
        VerifiableCredentials.Hotp.generate_hotp(
          secret,
          div(now, expiration) +
            VerifiableCredentials.Status.shift(:revoked)
        )

      suspended =
        VerifiableCredentials.Hotp.generate_hotp(
          revoked,
          div(now, expiration) +
            VerifiableCredentials.Status.shift(:suspended)
        )

      valid =
        VerifiableCredentials.Hotp.generate_hotp(
          suspended,
          div(now, expiration) +
            VerifiableCredentials.Status.shift(:valid)
        )

      {:ok, expiration: expiration, secret: secret, status_list: valid, now: now}
    end

    test "generate a valid salt", %{
      expiration: expiration,
      secret: secret,
      status_list: status_list,
      now: now
    } do
      status = :valid
      salt = VerifiableCredentials.Status.generate_status_token(secret, expiration, status)

      assert String.split(salt, "~") |> List.last() ==
               VerifiableCredentials.Hotp.generate_hotp(
                 status_list,
                 div(now, expiration) +
                   VerifiableCredentials.Status.shift(status)
               )

      assert VerifiableCredentials.Status.verify_status_token(secret, salt) == status
    end

    test "generate a suspended salt", %{
      expiration: expiration,
      secret: secret,
      status_list: status_list,
      now: now
    } do
      status = :suspended
      salt = VerifiableCredentials.Status.generate_status_token(secret, expiration, status)

      assert String.split(salt, "~") |> List.last() ==
               VerifiableCredentials.Hotp.generate_hotp(
                 status_list,
                 div(now, expiration) +
                   VerifiableCredentials.Status.shift(status)
               )

      assert VerifiableCredentials.Status.verify_status_token(secret, salt) == status
    end

    test "generate a revoked salt", %{
      expiration: expiration,
      secret: secret,
      status_list: status_list,
      now: now
    } do
      status = :revoked
      salt = VerifiableCredentials.Status.generate_status_token(secret, expiration, status)

      assert String.split(salt, "~") |> List.last() ==
               VerifiableCredentials.Hotp.generate_hotp(
                 status_list,
                 div(now, expiration) +
                   VerifiableCredentials.Status.shift(status)
               )

      assert VerifiableCredentials.Status.verify_status_token(secret, salt) == status
    end

    test "generate a thousand salt", %{
      expiration: expiration,
      secret: secret
    } do
      statuses = [:valid, :revoked, :suspended]

      salts =
        Enum.map(1..1_000, fn _ ->
          status = Enum.random(statuses)

          assert salt =
                   VerifiableCredentials.Status.generate_status_token(secret, expiration, status)

          {status, salt}
        end)

      Enum.map(salts, fn {status, salt} ->
        :timer.tc(fn ->
          assert VerifiableCredentials.Status.verify_status_token(secret, salt) == status
        end)
      end)
    end
  end

  describe "Status.verify_status_token/2" do
    test "returns invalid" do
      assert VerifiableCredentials.Status.verify_status_token("secret", "invalid salt") ==
               :invalid
    end
  end

  defp token_with_signatures_adapter(adapter) do
    client = insert(:client, signatures_adapter: Atom.to_string(adapter))
    insert(:token, client: client) |> to_oauth_schema()
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

  def private_key_fixture do
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVO\nf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa\n9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8Wd\nSq3dGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/\nU8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2t\npyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQABAoIBAG0dg/upL8k1IWiv\n8BNphrXIYLYQmiiBQTPJWZGvWIC2sl7i40yvCXjDjiRnZNK9HwgL94XtALCXYRFR\nJD41bRA3MO5A0HSPIWwJXwS10/cU56HVCNHjwKa6Rz/QiG2kNASMZEMzlvHtrjna\ndx36/sjI3HH8gh1BaTZyiuDE72SMkPbL838jfL1YY9uJ0u6hWFDbdn3sqPfJ6Cnz\n1cu0piT35nkilnIGCNYA0i3lyMeo4XrdXaAJdN9nnqbCi5ewQWqaHbrIIY5LTgzJ\nYlOr3IiecyokFxHCbULXle60u0KqXYgBHmlQJJr1Dj4c9AkQmefjC2jRMlhOrIzo\nIkIUeMECgYEA+MNLB+w6vv1ogqzM3M1OLt6bziWJCn+XkziuMrCiY9KeDD+S70+E\nhfbhM5RjCE3wxC/k59039laT973BmdMHxrDd2zSjOFmCIORv5yrD5oBHMaMZcwuQ\n45Xisi4aoQoOhyznSnjo/RjeQB7qEDzXFznLLNT79HzqyAtCWD3UIu8CgYEA2yik\n9FKl7HJEY94D2K6vNh1AHGnkwIQC72pXzlUrVuwQYngj6/Gkhw8ayFBApHfwVCXj\no9rDYPdNrrAs0Zz0JsiJp6bOCEKCrMYE16UiejUUAg/OZ5eg6+3m3/iWatkzLUuK\n1LIkVBJlEyY0uPuAaBF0V0VleNvfCGhVYOn46+ECgYAUD4OsduNh5YOZDiBTKgdF\nBlSgMiyz+QgbKjX6Bn6B+EkgibvqqonwV7FffHbkA40H9SjLfe52YhL6poXHRtpY\nroillcAX2jgBOQrBJJS5sNyM5y81NNiRUdP/NHKXS/1R71ATlF6NkoTRvOx5NL7P\ns6xryB0tYSl5ylamUQ4bZwKBgHF6FB9mA//wErVbKcayfIqajq2nrwh30kVBXQG7\nW9uAE+PIrWDoF/bOvWFnHHGMoOYRUFNxXKUCqDiBhFNs34aNY6lpV1kzhxIK3ksC\neF2qyhdfM9Kz0mEXJ+pkfw4INNWJPfNv4hueArPtnnMB1rUMBJ+DkU0JG+zwiPTL\ncVZBAoGBAM6kOsh5KGn3aI83g9ZO0TrKLXXFotxJt31Wu11ydj9K33/Qj3UXcxd4\nJPXr600F0DkLeUKBob6BALeHFWcrSz5FGLGRqdRxdv+L6g18WH5m2xEs7o6M6e5I\nIhyUC60ZewJ2M8rV4KgCJJdZE2kENlSgjU92IDVPT9Oetrc7hQJd\n-----END RSA PRIVATE KEY-----\n\n"
  end
end
