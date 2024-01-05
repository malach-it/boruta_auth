defmodule Boruta.VerifiableCredentialsTest do
  use ExUnit.Case

  alias Boruta.Config
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.VerifiableCredentials

  describe "issue_verifiable_credential/3" do
    setup do
      {_, public_jwk} = public_key_fixture() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map()
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "jwk" => public_jwk,
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{
        "aud" => Config.issuer(),
        "iat" => :os.system_time(:seconds)
      }, signer)

      proof = %{
        "type" => "jwt",
        "proof" => token
      }

      resource_owner = %ResourceOwner{sub: SecureRandom.uuid(), extra_claims: %{
        "firstname" => "firstname"
      }}

      credential_identifier = "credential_identifier"

      credential_configuration = %{
        claims: %{
          "credential_identifier" => ["firstname"]
        }
      }

      {:ok,
       proof: proof,
       resource_owner: resource_owner,
       credential_identifier: credential_identifier,
       credential_configuration: credential_configuration,
       signer: signer}
    end

    # test "verifies proof - prints the proof", %{proof: proof} do
    #   dbg(proof)
    #   dbg(Joken.peek_header(proof["proof"]))
    #   dbg(Joken.peek_claims(proof["proof"]))
    # end

    test "verifies proof - proof format", %{
      resource_owner: resource_owner,
      credential_identifier: credential_identifier,
      credential_configuration: credential_configuration
    } do
      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_identifier,
               credential_configuration,
               %{}
             ) ==
               {:error,
                "Proof validation failed. Required properties type, proof are missing at #."}
    end

    test "verifies proof - header claims", %{
      resource_owner: resource_owner,
      credential_identifier: credential_identifier,
      credential_configuration: credential_configuration
    } do
      signer = Joken.Signer.create("HS256", "secret", %{})

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "type" => "jwt",
        "proof" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_identifier,
               credential_configuration,
               proof
             ) ==
               {:error,
                "Proof JWT must be asymetrically signed, Proof JWT must have `openid4vci-proof+jwt` typ header, No proof key material found in JWT headers."}
    end

    test "verifies proof - the algorithm is asymetric", %{
      resource_owner: resource_owner,
      credential_identifier: credential_identifier,
      credential_configuration: credential_configuration
    } do
      signer =
        Joken.Signer.create("HS256", "secret", %{"kid" => "kid", "typ" => "openid4vci-proof+jwt"})

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "type" => "jwt",
        "proof" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_identifier,
               credential_configuration,
               proof
             ) == {:error, "Proof JWT must be asymetrically signed."}
    end

    test "verifies proof - typ header", %{
      resource_owner: resource_owner,
      credential_identifier: credential_identifier,
      credential_configuration: credential_configuration
    } do
      signer = Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{"kid" => "kid"})

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "type" => "jwt",
        "proof" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_identifier,
               credential_configuration,
               proof
             ) == {:error, "Proof JWT must have `openid4vci-proof+jwt` typ header."}
    end

    test "verifies proof - must have proof material", %{
      resource_owner: resource_owner,
      credential_identifier: credential_identifier,
      credential_configuration: credential_configuration
    } do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "typ" => "openid4vci-proof+jwt"
        })

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "type" => "jwt",
        "proof" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_identifier,
               credential_configuration,
               proof
             ) == {:error, "No proof key material found in JWT headers."}
    end

    test "verifies proof - must have required claims", %{
      resource_owner: resource_owner,
      credential_identifier: credential_identifier,
      credential_configuration: credential_configuration
    } do
      signer =
        Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
          "typ" => "openid4vci-proof+jwt",
          "kid" => "kid"
        })

      {:ok, token, _claims} = VerifiableCredentials.Token.generate_and_sign(%{}, signer)

      proof = %{
        "type" => "jwt",
        "proof" => token
      }

      assert VerifiableCredentials.issue_verifiable_credential(
               resource_owner,
               credential_identifier,
               credential_configuration,
               proof
             ) ==
               {:error,
                "Proof does not contain valid JWT claims, `aud` and `iat` claims are required."}
    end

    # test "issues credential", %{
    #   proof: proof,
    #   resource_owner: resource_owner,
    #   credential_identifier: credential_identifier,
    #   credential_configuration: credential_configuration
    # } do
    #   assert VerifiableCredentials.issue_verifiable_credential(
    #            resource_owner,
    #            credential_identifier,
    #            credential_configuration,
    #            proof
    #          ) == proof
    #   # TODO issue credential
    # end
  end

  def public_key_fixture do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def private_key_fixture do
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVO\nf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa\n9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8Wd\nSq3dGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/\nU8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2t\npyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQABAoIBAG0dg/upL8k1IWiv\n8BNphrXIYLYQmiiBQTPJWZGvWIC2sl7i40yvCXjDjiRnZNK9HwgL94XtALCXYRFR\nJD41bRA3MO5A0HSPIWwJXwS10/cU56HVCNHjwKa6Rz/QiG2kNASMZEMzlvHtrjna\ndx36/sjI3HH8gh1BaTZyiuDE72SMkPbL838jfL1YY9uJ0u6hWFDbdn3sqPfJ6Cnz\n1cu0piT35nkilnIGCNYA0i3lyMeo4XrdXaAJdN9nnqbCi5ewQWqaHbrIIY5LTgzJ\nYlOr3IiecyokFxHCbULXle60u0KqXYgBHmlQJJr1Dj4c9AkQmefjC2jRMlhOrIzo\nIkIUeMECgYEA+MNLB+w6vv1ogqzM3M1OLt6bziWJCn+XkziuMrCiY9KeDD+S70+E\nhfbhM5RjCE3wxC/k59039laT973BmdMHxrDd2zSjOFmCIORv5yrD5oBHMaMZcwuQ\n45Xisi4aoQoOhyznSnjo/RjeQB7qEDzXFznLLNT79HzqyAtCWD3UIu8CgYEA2yik\n9FKl7HJEY94D2K6vNh1AHGnkwIQC72pXzlUrVuwQYngj6/Gkhw8ayFBApHfwVCXj\no9rDYPdNrrAs0Zz0JsiJp6bOCEKCrMYE16UiejUUAg/OZ5eg6+3m3/iWatkzLUuK\n1LIkVBJlEyY0uPuAaBF0V0VleNvfCGhVYOn46+ECgYAUD4OsduNh5YOZDiBTKgdF\nBlSgMiyz+QgbKjX6Bn6B+EkgibvqqonwV7FffHbkA40H9SjLfe52YhL6poXHRtpY\nroillcAX2jgBOQrBJJS5sNyM5y81NNiRUdP/NHKXS/1R71ATlF6NkoTRvOx5NL7P\ns6xryB0tYSl5ylamUQ4bZwKBgHF6FB9mA//wErVbKcayfIqajq2nrwh30kVBXQG7\nW9uAE+PIrWDoF/bOvWFnHHGMoOYRUFNxXKUCqDiBhFNs34aNY6lpV1kzhxIK3ksC\neF2qyhdfM9Kz0mEXJ+pkfw4INNWJPfNv4hueArPtnnMB1rUMBJ+DkU0JG+zwiPTL\ncVZBAoGBAM6kOsh5KGn3aI83g9ZO0TrKLXXFotxJt31Wu11ydj9K33/Qj3UXcxd4\nJPXr600F0DkLeUKBob6BALeHFWcrSz5FGLGRqdRxdv+L6g18WH5m2xEs7o6M6e5I\nIhyUC60ZewJ2M8rV4KgCJJdZE2kENlSgjU92IDVPT9Oetrc7hQJd\n-----END RSA PRIVATE KEY-----\n\n"
  end
end
