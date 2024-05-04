defmodule Boruta.VerifiableCredentialsTest do
  use Boruta.DataCase, async: true

  import Boruta.Factory

  alias Boruta.Config
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.VerifiableCredentials

  describe "issue_verifiable_credential/4" do
    setup do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "kid" => "did:jwk:eyJlIjoiQVFBQiIsImt0eSI6IlJTQSIsIm4iOiIxUGFQX2diWGl4NWl0alJDYWVndklfQjNhRk9lb3hsd1BQTHZmTEhHQTRRZkRtVk9mOGNVOE91WkZBWXpMQXJXM1BubndXV3kzOW5WSk94NDJRUlZHQ0dkVUNtVjdzaERIUnNyODYtMkRsTDdwd1VhOVF5SHNUajg0ZkFKbjJGdjloOW1xckl2VXpBdEVZUmxHRnZqVlRHQ3d6RXVsbHBzQjBHSmFmb3BVVEZieThXZFNxM2RHTEpCQjFyLVE4UXRabkF4eHZvbGh3T21Za0Jra2lkZWZtbTQ4WDdoRlhMMmNTSm0yRzd3UXlpbk9leV9VOHhEWjY4bWdUYWtpcVMyUnRqbkZEMGRucEJsNUNZVGU0czZvWktFeUZpRk5pVzRLa1IxR1Zqc0t3WTlvQzJ0cHlRMEFFVU12azlUOVZkSWx0U0lpQXZPS2x3RnpMNDljZ3daRHcifQ",
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
          "credential_identifier" => %{
            version: "13",
            types: ["VerifiableCredential"],
            time_to_live: 3600,
            format: "jwt_vc",
            claims: [%{
              "name" => "firstname",
              "label" => "firstname",
              "pointer" => "firstname",
              "expiration" => "3600"
            }]
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

    # test "verifies proof - prints the proof", %{proof: proof} do
    #   dbg(proof)
    #   dbg(Joken.peek_header(proof["jwt"]))
    #   dbg(Joken.peek_claims(proof["jwt"]))
    # end

    test "verifies proof - proof format", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               Map.put(credential_params, "proof", %{}),
               insert(:client),
               %{}
             ) ==
               {:error,
                "Proof validation failed. Required properties proof_type, jwt are missing at #."}
    end

    test "verifies proof - header claims", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      signer = Joken.Signer.create("HS256", "secret", %{})

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               Map.put(credential_params, "proof", proof),
               insert(:client),
               %{}
             ) ==
               {:error,
                "Proof JWT must be asymetrically signed, Proof JWT must have `openid4vci-proof+jwt` typ header, No proof key material found in JWT headers."}
    end

    test "verifies proof - the algorithm is asymetric", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      signer =
        Joken.Signer.create("HS256", "secret", %{"kid" => "kid", "typ" => "openid4vci-proof+jwt"})

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               Map.put(credential_params, "proof", proof),
               insert(:client),
               %{}
             ) == {:error, "Proof JWT must be asymetrically signed."}
    end

    test "verifies proof - typ header", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      signer = Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{"kid" => "kid"})

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               Map.put(credential_params, "proof", proof),
               insert(:client),
               %{}
             ) == {:error, "Proof JWT must have `openid4vci-proof+jwt` typ header."}
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
               insert(:client),
               %{}
             ) == {:error, "No proof key material found in JWT headers."}
    end

    test "verifies proof - must have required claims", %{
      resource_owner: resource_owner,
      credential_params: credential_params
    } do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "typ" => "openid4vci-proof+jwt",
          "kid" => "kid"
        })

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "proof_type" => "jwt",
        "jwt" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               Map.put(credential_params, "proof", proof),
               insert(:client),
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
                 insert(:client),
                 %{}
               )

      # TODO validate credential body
      assert credential
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
          "credential_identifier" => %{
            version: "13",
            types: ["VerifiableCredential"],
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
                 insert(:client),
                 %{}
               )

      # TODO validate credential body
      assert credential
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
          "credential_identifier" => %{
            version: "13",
            types: ["VerifiableCredential"],
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
                 insert(:client),
                 %{}
               )

      # TODO validate credential body
      assert credential
    end

    test "issues vc+sd-jwt credential - valid", %{
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
          "credential_identifier" => %{
            version: "13",
            types: ["VerifiableCredential"],
            format: "vc+sd-jwt",
            claims: [%{
              "name" => "firstname",
              "label" => "firstname",
              "pointer" => "firstname",
              "expiration" => "3600"
            }],
            time_to_live: 60
          }
        }
      }
      client = insert(:client)
      assert {:ok,
              %{
                credential: credential,
                format: "vc+sd-jwt"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 client,
                 %{}
               )

      # TODO validate credential body
      assert credential
      suspended_salt_key = String.split(credential, "~")
                   |> Enum.at(1)
                   |> Base.url_decode64!(padding: false)
                   |> Jason.decode!()
                   |> List.first()
                   |> String.split("~")
                   |> List.last()

      assert suspended_salt_key == VerifiableCredentials.Hotp.generate_hotp(
        client.private_key,
        div(:os.system_time(:seconds), 3600) + 33
      )
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
          "credential_identifier" => %{
            version: "13",
            types: ["VerifiableCredential"],
            format: "vc+sd-jwt",
            claims: [%{
              "name" => "firstname",
              "label" => "firstname",
              "pointer" => "firstname",
              "expiration" => "3600"
            }],
            time_to_live: 60
          }
        }
      }
      client = insert(:client)
      assert {:ok,
              %{
                credential: credential,
                format: "vc+sd-jwt"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 client,
                 %{}
               )

      # TODO validate credential body
      assert credential
      suspended_salt_key = String.split(credential, "~")
                   |> Enum.at(1)
                   |> Base.url_decode64!(padding: false)
                   |> Jason.decode!()
                   |> List.first()
                   |> String.split("~")
                   |> List.last()

      assert suspended_salt_key == VerifiableCredentials.Hotp.generate_hotp(
        client.private_key,
        div(:os.system_time(:seconds), 3600) + 55
      )
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
          "credential_identifier" => %{
            version: "13",
            types: ["VerifiableCredential"],
            format: "vc+sd-jwt",
            claims: [%{
              "name" => "firstname",
              "label" => "firstname",
              "pointer" => "firstname",
              "expiration" => "3600"
            }],
            time_to_live: 60
          }
        }
      }
      client = insert(:client)
      assert {:ok,
              %{
                credential: credential,
                format: "vc+sd-jwt"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 client,
                 %{}
               )

      # TODO validate credential body
      assert credential
      suspended_salt_key = String.split(credential, "~")
                   |> Enum.at(1)
                   |> Base.url_decode64!(padding: false)
                   |> Jason.decode!()
                   |> List.first()
                   |> String.split("~")
                   |> List.last()

      assert suspended_salt_key == VerifiableCredentials.Hotp.generate_hotp(
        client.private_key,
        div(:os.system_time(:seconds), 3600) + 44
      )
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
          "credential_identifier" => %{
            version: "13",
            types: ["VerifiableCredential"],
            format: "vc+sd-jwt",
            claims: [%{
              "name" => "firstname",
              "label" => "firstname",
              "pointer" => "firstname",
              "expiration" => "1"
            }],
            time_to_live: 60
          }
        }
      }
      client = insert(:client)
      assert {:ok,
              %{
                credential: credential,
                format: "vc+sd-jwt"
              }} =
               VerifiableCredentials.issue_verifiable_credential(
                 resource_owner,
                 credential_params,
                 client,
                 %{}
               )

      :timer.sleep(1000)
      # TODO validate credential body
      assert credential
      suspended_salt_key = String.split(credential, "~")
                   |> Enum.at(1)
                   |> Base.url_decode64!(padding: false)
                   |> Jason.decode!()
                   |> List.first()
                   |> String.split("~")
                   |> List.last()

      refute suspended_salt_key == VerifiableCredentials.Hotp.generate_hotp(
        client.private_key,
        div(:os.system_time(:seconds), 3600) + 33
      )
      refute suspended_salt_key == VerifiableCredentials.Hotp.generate_hotp(
        client.private_key,
        div(:os.system_time(:seconds), 3600) + 44
      )
      refute suspended_salt_key == VerifiableCredentials.Hotp.generate_hotp(
        client.private_key,
        div(:os.system_time(:seconds), 3600) + 55
      )
    end
  end

  describe "generate_sd_salt/3" do
    test "generate a ten years valid salt" do
      secret = "secret"
      expiration = 3600 * 24 * 365 * 10
      :binary.encode_unsigned(expiration) |> :binary.bin_to_list()
      status = :valid
      salt = VerifiableCredentials.generate_sd_salt(secret, expiration, status)

      assert String.split(salt, "~") |> List.last() == VerifiableCredentials.Hotp.generate_hotp(
        secret,
        div(:os.system_time(:seconds), expiration) + 33
      )
      assert VerifiableCredentials.verify_salt(secret, salt) == :valid
    end

    test "generate a valid salt" do
      secret = "secret"
      expiration = 60
      status = :valid
      salt = VerifiableCredentials.generate_sd_salt(secret, expiration, status)

      assert String.split(salt, "~") |> List.last() == VerifiableCredentials.Hotp.generate_hotp(
        secret,
        div(:os.system_time(:seconds), expiration) + 33
      )
      assert VerifiableCredentials.verify_salt(secret, salt) == :valid
    end

    test "generate a thousand salt" do
      statuses = [:valid, :revoked, :suspended]
      secret = "secret"

      salts = Enum.map(1..1_000, fn _ ->
        status = Enum.random(statuses)
        expiration = Enum.random(1..3600)

        assert salt = VerifiableCredentials.generate_sd_salt(secret, expiration, status)
        {status, salt}
      end)

      Enum.map(salts, fn {status, salt} ->
        :timer.tc(fn ->
          assert VerifiableCredentials.verify_salt(secret, salt) == status
        end)
      end)
    end

    test "generate a revoked salt" do
      secret = "secret"
      expiration = 60
      status = :revoked
      salt = VerifiableCredentials.generate_sd_salt(secret, expiration, status)

      assert String.split(salt, "~") |> List.last() == VerifiableCredentials.Hotp.generate_hotp(
        secret,
        div(:os.system_time(:seconds), expiration) + 44
      )
      assert VerifiableCredentials.verify_salt(secret, salt) == :revoked
    end

    test "generate a suspended salt" do
      secret = "secret"
      expiration = 60
      status = :suspended
      salt = VerifiableCredentials.generate_sd_salt(secret, expiration, status)

      assert String.split(salt, "~") |> List.last() == VerifiableCredentials.Hotp.generate_hotp(
        secret,
        div(:os.system_time(:seconds), expiration) + 55
      )
      assert VerifiableCredentials.verify_salt(secret, salt) == :suspended
    end
  end

  describe "verify_salt/2" do
    test "returns invalid" do
      assert VerifiableCredentials.verify_salt("secret", "invalid salt") == :invalid
    end
  end

  def public_key_fixture do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def private_key_fixture do
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVO\nf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa\n9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8Wd\nSq3dGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/\nU8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2t\npyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQABAoIBAG0dg/upL8k1IWiv\n8BNphrXIYLYQmiiBQTPJWZGvWIC2sl7i40yvCXjDjiRnZNK9HwgL94XtALCXYRFR\nJD41bRA3MO5A0HSPIWwJXwS10/cU56HVCNHjwKa6Rz/QiG2kNASMZEMzlvHtrjna\ndx36/sjI3HH8gh1BaTZyiuDE72SMkPbL838jfL1YY9uJ0u6hWFDbdn3sqPfJ6Cnz\n1cu0piT35nkilnIGCNYA0i3lyMeo4XrdXaAJdN9nnqbCi5ewQWqaHbrIIY5LTgzJ\nYlOr3IiecyokFxHCbULXle60u0KqXYgBHmlQJJr1Dj4c9AkQmefjC2jRMlhOrIzo\nIkIUeMECgYEA+MNLB+w6vv1ogqzM3M1OLt6bziWJCn+XkziuMrCiY9KeDD+S70+E\nhfbhM5RjCE3wxC/k59039laT973BmdMHxrDd2zSjOFmCIORv5yrD5oBHMaMZcwuQ\n45Xisi4aoQoOhyznSnjo/RjeQB7qEDzXFznLLNT79HzqyAtCWD3UIu8CgYEA2yik\n9FKl7HJEY94D2K6vNh1AHGnkwIQC72pXzlUrVuwQYngj6/Gkhw8ayFBApHfwVCXj\no9rDYPdNrrAs0Zz0JsiJp6bOCEKCrMYE16UiejUUAg/OZ5eg6+3m3/iWatkzLUuK\n1LIkVBJlEyY0uPuAaBF0V0VleNvfCGhVYOn46+ECgYAUD4OsduNh5YOZDiBTKgdF\nBlSgMiyz+QgbKjX6Bn6B+EkgibvqqonwV7FffHbkA40H9SjLfe52YhL6poXHRtpY\nroillcAX2jgBOQrBJJS5sNyM5y81NNiRUdP/NHKXS/1R71ATlF6NkoTRvOx5NL7P\ns6xryB0tYSl5ylamUQ4bZwKBgHF6FB9mA//wErVbKcayfIqajq2nrwh30kVBXQG7\nW9uAE+PIrWDoF/bOvWFnHHGMoOYRUFNxXKUCqDiBhFNs34aNY6lpV1kzhxIK3ksC\neF2qyhdfM9Kz0mEXJ+pkfw4INNWJPfNv4hueArPtnnMB1rUMBJ+DkU0JG+zwiPTL\ncVZBAoGBAM6kOsh5KGn3aI83g9ZO0TrKLXXFotxJt31Wu11ydj9K33/Qj3UXcxd4\nJPXr600F0DkLeUKBob6BALeHFWcrSz5FGLGRqdRxdv+L6g18WH5m2xEs7o6M6e5I\nIhyUC60ZewJ2M8rV4KgCJJdZE2kENlSgjU92IDVPT9Oetrc7hQJd\n-----END RSA PRIVATE KEY-----\n\n"
  end
end
