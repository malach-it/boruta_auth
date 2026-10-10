defmodule Boruta.HttpSigTest do
  use ExUnit.Case, async: true

  alias Boruta.HttpSig

  setup do
    signer =
      Joken.Signer.create("RS512", %{"pem" => valid_private_key()}, %{
        "typ" => "aa-agent+jwt"
      })

    public_jwk = valid_public_key() |> JOSE.JWK.from_pem() |> JOSE.JWK.to_map() |> elem(1)

    {:ok, sig_jwt, _claims} =
      Joken.encode_and_sign(
        %{
          iss: "https://host.test",
          cnf: %{
            jwk: public_jwk
          }
        },
        signer
      )

    {:ok, sig_jwt: sig_jwt, signer: signer, public_jwk: public_jwk}
  end

  test "returns an error with unsupported scheme" do
    assert {:error, "Agent token signature scheme not supported."} =
             HttpSig.validate(%{
               req_headers: [
                 {"signature-key", ~s(sig=hwk;key="value")}
               ]
             })
  end

  test "returns an error with invalid agent token" do
    assert {:error, "Agent token header is invalid."} =
             HttpSig.validate(%{
               req_headers: [
                 {"signature-key", ~s(sig=jwt;jwt="jwt")}
               ]
             })
  end

  test "returns an error with multiple signature key headers" do
    assert {:error, "More than one Signature-Key header present in the request."} =
             HttpSig.validate(%{
               req_headers: [
                 {"signature-key", ~s(sig=jwt;jwt="jwta")},
                 {"signature-key", ~s(sig=jwt;jwt="jwtb")}
               ]
             })
  end

  test "returns an error without cnf jwk key", %{
    signer: signer,
  } do
    {:ok, sig_jwt, _claims} =
      Joken.encode_and_sign(%{iss: "https://host.test"}, signer)

    assert {:error, "Agent token must contain a cnf jwk key."} =
             HttpSig.validate(%{
               scheme: "https",
               host: "host.test",
               req_headers: [
                 {"signature-key", ~s(sig1=jwt;jwt="#{sig_jwt}"")}
               ]
             })
  end

  test "returns an error with an invalid host", %{
    sig_jwt: sig_jwt,
    signer: signer,
    public_jwk: public_jwk
  } do
    {:ok, sig2_jwt, _claims} =
      Joken.encode_and_sign(%{iss: "https://host.test", cnf: %{jwk: public_jwk}}, signer)

    assert {:error, "Request host do not match agent token issuer."} =
             HttpSig.validate(%{
               scheme: "https",
               host: "invalid.test",
               req_headers: [
                 {"signature-key", ~s(sig1=jwt;jwt="#{sig_jwt}",sig2=jwt;jwt="#{sig2_jwt}")}
               ]
             })
  end

  test "validates multiple signatures", %{
    sig_jwt: sig_jwt,
    signer: signer,
    public_jwk: public_jwk
  } do
    {:ok, sig2_jwt, _claims} =
      Joken.encode_and_sign(%{iss: "https://host.test", cnf: %{jwk: public_jwk}}, signer)

    assert :ok =
             HttpSig.validate(%{
               scheme: "https",
               host: "host.test",
               req_headers: [
                 {"signature-key", ~s(sig1=jwt;jwt="#{sig_jwt}",sig2=jwt;jwt="#{sig2_jwt}")}
               ]
             })
  end

  test "validates a signature", %{sig_jwt: sig_jwt} do
    assert :ok =
             HttpSig.validate(%{
               scheme: "https",
               host: "host.test",
               req_headers: [{"signature-key", ~s(sig=jwt;jwt="#{sig_jwt}")}]
             })
  end

  def valid_public_key do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def valid_private_key do
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVO\nf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa\n9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8Wd\nSq3dGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/\nU8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2t\npyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQABAoIBAG0dg/upL8k1IWiv\n8BNphrXIYLYQmiiBQTPJWZGvWIC2sl7i40yvCXjDjiRnZNK9HwgL94XtALCXYRFR\nJD41bRA3MO5A0HSPIWwJXwS10/cU56HVCNHjwKa6Rz/QiG2kNASMZEMzlvHtrjna\ndx36/sjI3HH8gh1BaTZyiuDE72SMkPbL838jfL1YY9uJ0u6hWFDbdn3sqPfJ6Cnz\n1cu0piT35nkilnIGCNYA0i3lyMeo4XrdXaAJdN9nnqbCi5ewQWqaHbrIIY5LTgzJ\nYlOr3IiecyokFxHCbULXle60u0KqXYgBHmlQJJr1Dj4c9AkQmefjC2jRMlhOrIzo\nIkIUeMECgYEA+MNLB+w6vv1ogqzM3M1OLt6bziWJCn+XkziuMrCiY9KeDD+S70+E\nhfbhM5RjCE3wxC/k59039laT973BmdMHxrDd2zSjOFmCIORv5yrD5oBHMaMZcwuQ\n45Xisi4aoQoOhyznSnjo/RjeQB7qEDzXFznLLNT79HzqyAtCWD3UIu8CgYEA2yik\n9FKl7HJEY94D2K6vNh1AHGnkwIQC72pXzlUrVuwQYngj6/Gkhw8ayFBApHfwVCXj\no9rDYPdNrrAs0Zz0JsiJp6bOCEKCrMYE16UiejUUAg/OZ5eg6+3m3/iWatkzLUuK\n1LIkVBJlEyY0uPuAaBF0V0VleNvfCGhVYOn46+ECgYAUD4OsduNh5YOZDiBTKgdF\nBlSgMiyz+QgbKjX6Bn6B+EkgibvqqonwV7FffHbkA40H9SjLfe52YhL6poXHRtpY\nroillcAX2jgBOQrBJJS5sNyM5y81NNiRUdP/NHKXS/1R71ATlF6NkoTRvOx5NL7P\ns6xryB0tYSl5ylamUQ4bZwKBgHF6FB9mA//wErVbKcayfIqajq2nrwh30kVBXQG7\nW9uAE+PIrWDoF/bOvWFnHHGMoOYRUFNxXKUCqDiBhFNs34aNY6lpV1kzhxIK3ksC\neF2qyhdfM9Kz0mEXJ+pkfw4INNWJPfNv4hueArPtnnMB1rUMBJ+DkU0JG+zwiPTL\ncVZBAoGBAM6kOsh5KGn3aI83g9ZO0TrKLXXFotxJt31Wu11ydj9K33/Qj3UXcxd4\nJPXr600F0DkLeUKBob6BALeHFWcrSz5FGLGRqdRxdv+L6g18WH5m2xEs7o6M6e5I\nIhyUC60ZewJ2M8rV4KgCJJdZE2kENlSgjU92IDVPT9Oetrc7hQJd\n-----END RSA PRIVATE KEY-----\n\n"
  end
end
