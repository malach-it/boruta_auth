defmodule Boruta.Oauth.Authorization.ClientTest do
  use Boruta.DataCase

  import Boruta.Factory

  defmodule Token do
    @moduledoc false

    use Joken.Config, default_signer: :pem_rs512
  end

  alias Boruta.Oauth.Authorization.Client
  alias Boruta.Oauth.Error

  describe "authorize/1" do
    test "returns an error with bad auth method (client_secret_post)" do
      client = insert(:client, token_endpoint_auth_methods: ["client_secret_post"])
      source = %{type: "basic", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with POST body parameters."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")

      source = %{type: "jwt", value: "value"}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with POST body parameters."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with bad auth method (client_secret_basc)" do
      client = insert(:client, token_endpoint_auth_methods: ["client_secret_basic"])
      source = %{type: "post", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with BasicAuth."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")

      source = %{type: "jwt", value: "value"}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with BasicAuth."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with bad auth method (client_secret_jwt)" do
      client = insert(:client, token_endpoint_auth_methods: ["client_secret_jwt"])
      source = %{type: "post", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with a jwt assertion."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")

      source = %{type: "basic", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with a jwt assertion."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with bad auth method (private_key_jwt)" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["private_key_jwt"],
          token_endpoint_jwt_auth_alg: "RS512",
          jwt_public_key: valid_public_key()
        )

      source = %{type: "post", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with a jwt assertion."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")

      source = %{type: "basic", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Given client expects the credentials to be provided with a jwt assertion."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with bad auth method (private_key_jwt with bad configuration)" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["private_key_jwt"],
          token_endpoint_jwt_auth_alg: "HS512",
          jwt_public_key: valid_public_key()
        )

      source = %{type: "jwt", value: client.secret}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description:
                  "Bad client jwt authentication method configuration (jwks and token endpoint jwt auth algorithm do not match)."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "authorizes with post auth method" do
      client = insert(:client, token_endpoint_auth_methods: ["client_secret_post"])
      source = %{type: "post", value: client.secret}

      assert {:ok, _client} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "authorizes with basic auth method" do
      client = insert(:client, token_endpoint_auth_methods: ["client_secret_basic"])
      source = %{type: "basic", value: client.secret}

      assert {:ok, _client} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "authorizes with client secret jwt auth method" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["client_secret_jwt"],
          token_endpoint_jwt_auth_alg: "HS512"
        )

      signer = Joken.Signer.create("HS512", client.secret)
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)
      source = %{type: "jwt", value: client_assertion}

      assert {:ok, _client} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with nil client secret jwt auth method" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["client_secret_jwt"],
          token_endpoint_jwt_auth_alg: "HS512"
        )

      source = %{type: "jwt", value: nil}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description: "The given client secret jwt does not match signature key."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with bad client secret jwt auth method" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["client_secret_jwt"],
          token_endpoint_jwt_auth_alg: "HS512"
        )

      signer = Joken.Signer.create("HS512", "bad secret")
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)
      source = %{type: "jwt", value: client_assertion}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description: "The given client secret jwt does not match signature key."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "authorizes with private key jwt auth method" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["private_key_jwt"],
          token_endpoint_jwt_auth_alg: "RS512",
          jwt_public_key: valid_public_key()
        )

      signer = Joken.Signer.create("RS512", %{"pem" => valid_private_key()})
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)
      source = %{type: "jwt", value: client_assertion}

      assert {:ok, _client} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "authorizes with private key jwt auth method with key rotation" do
      bypass = Bypass.open()
      jwks_uri = "http://localhost:#{bypass.port}/jwks"

      client =
        insert(:client,
          token_endpoint_auth_methods: ["private_key_jwt"],
          token_endpoint_jwt_auth_alg: "RS512",
          jwt_public_key: valid_public_key(),
          jwks_uri: jwks_uri
        )

      signer = Joken.Signer.create("RS512", %{"pem" => other_valid_private_key()})
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)
      source = %{type: "jwt", value: client_assertion}

      {_, jwk} = JOSE.JWK.from_pem(other_valid_public_key()) |> JOSE.JWK.to_map()
      jwk = Map.put(jwk, "alg", "RS512")
      Bypass.expect_once(bypass, "GET", "/jwks", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"keys" => [jwk]}))
      end)

      assert {:ok, _client} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with nil private key jwt auth method" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["private_key_jwt"],
          token_endpoint_jwt_auth_alg: "RS512",
          jwt_public_key: valid_public_key()
        )

      source = %{type: "jwt", value: nil}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description: "The given client secret jwt does not match signature key."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end

    test "returns an error with bad private key jwt auth method" do
      client =
        insert(:client,
          token_endpoint_auth_methods: ["private_key_jwt"],
          token_endpoint_jwt_auth_alg: "RS512",
          jwt_public_key: valid_public_key()
        )

      signer = Joken.Signer.create("RS512", %{"pem" => invalid_private_key()})
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)
      source = %{type: "jwt", value: client_assertion}

      assert {:error,
              %Error{
                error: :invalid_client,
                error_description: "The given client secret jwt does not match signature key."
              }} =
               Client.authorize(id: client.id, source: source, grant_type: "client_credentials")
    end
  end

  def valid_public_key do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end

  def valid_private_key do
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVO\nf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa\n9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8Wd\nSq3dGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/\nU8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2t\npyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQABAoIBAG0dg/upL8k1IWiv\n8BNphrXIYLYQmiiBQTPJWZGvWIC2sl7i40yvCXjDjiRnZNK9HwgL94XtALCXYRFR\nJD41bRA3MO5A0HSPIWwJXwS10/cU56HVCNHjwKa6Rz/QiG2kNASMZEMzlvHtrjna\ndx36/sjI3HH8gh1BaTZyiuDE72SMkPbL838jfL1YY9uJ0u6hWFDbdn3sqPfJ6Cnz\n1cu0piT35nkilnIGCNYA0i3lyMeo4XrdXaAJdN9nnqbCi5ewQWqaHbrIIY5LTgzJ\nYlOr3IiecyokFxHCbULXle60u0KqXYgBHmlQJJr1Dj4c9AkQmefjC2jRMlhOrIzo\nIkIUeMECgYEA+MNLB+w6vv1ogqzM3M1OLt6bziWJCn+XkziuMrCiY9KeDD+S70+E\nhfbhM5RjCE3wxC/k59039laT973BmdMHxrDd2zSjOFmCIORv5yrD5oBHMaMZcwuQ\n45Xisi4aoQoOhyznSnjo/RjeQB7qEDzXFznLLNT79HzqyAtCWD3UIu8CgYEA2yik\n9FKl7HJEY94D2K6vNh1AHGnkwIQC72pXzlUrVuwQYngj6/Gkhw8ayFBApHfwVCXj\no9rDYPdNrrAs0Zz0JsiJp6bOCEKCrMYE16UiejUUAg/OZ5eg6+3m3/iWatkzLUuK\n1LIkVBJlEyY0uPuAaBF0V0VleNvfCGhVYOn46+ECgYAUD4OsduNh5YOZDiBTKgdF\nBlSgMiyz+QgbKjX6Bn6B+EkgibvqqonwV7FffHbkA40H9SjLfe52YhL6poXHRtpY\nroillcAX2jgBOQrBJJS5sNyM5y81NNiRUdP/NHKXS/1R71ATlF6NkoTRvOx5NL7P\ns6xryB0tYSl5ylamUQ4bZwKBgHF6FB9mA//wErVbKcayfIqajq2nrwh30kVBXQG7\nW9uAE+PIrWDoF/bOvWFnHHGMoOYRUFNxXKUCqDiBhFNs34aNY6lpV1kzhxIK3ksC\neF2qyhdfM9Kz0mEXJ+pkfw4INNWJPfNv4hueArPtnnMB1rUMBJ+DkU0JG+zwiPTL\ncVZBAoGBAM6kOsh5KGn3aI83g9ZO0TrKLXXFotxJt31Wu11ydj9K33/Qj3UXcxd4\nJPXr600F0DkLeUKBob6BALeHFWcrSz5FGLGRqdRxdv+L6g18WH5m2xEs7o6M6e5I\nIhyUC60ZewJ2M8rV4KgCJJdZE2kENlSgjU92IDVPT9Oetrc7hQJd\n-----END RSA PRIVATE KEY-----\n\n"
  end

  def other_valid_private_key do
    "-----BEGIN PRIVATE KEY-----\nMIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAN0Mhw3A4JqMERW8\nObFDLBYOMnmIDo3BJo9h8OYGlahXeCt1rvoNNHnNo3lRy6nasZR4CE+brZHU9qq9\nNukoyy6+qBddidwQ3Sh3T98GqCh8IEWh0F84i8ZAoVXURCS+s4I/SbA7JjiS3zvw\njUklk55fGm90jEArzF+JUH2LsSGFAgMBAAECgYAwRrEkLtCe0CJXFeGftiTluDoL\n0swi52EthV1gT2XV+yxyiWQqlkG0rFWchGGveeS4oTJneH+CzvkENwjMCS2+Yssl\nBrlR5OkLq3zPvEcLXXCsSGvqQUnNusCN40RtKh3sux7L649PPQaH7B4X0UZHGz61\nHs1Z14ridVu/g5pVTQJBAPZBLgEcZECjW9P0vVgJYB+usHP6q+PvYYiS048QjXv3\neA8edSsnRAHbzuVkxR53lOh2VmV34GvNkg0VdmNJIkcCQQDly/zXUKST2CHfWrdZ\nZe4S3FSS3kqfiJyDSdMiqInj5vfxnNdAzWEgpAqtgftbAqHb/ElS28WO3ik3pw+K\nPpfTAkBkigYDVBkmPsvuBJ0NhX5mUQcfwvdM714NyYxwe5yYQVgWLCRAQx7D939I\nLtU/9CiqpC3v7XqF6P85MksMjD5fAkEAkV0Nr2K7CS8Slki7bRjWliW8dj+Z8vsn\nDsH3hpgYygsEU1nErKB+zXgXrRRpXXP30cHw3DJb8XlFl4fdg7T+swJARSmj5ToA\nQaBAGS9/b1Nvx3ZB8byZI9KF7DWbkpIe7RgxOlIMnRvl1lBMUWbg396MZ6jwp5I0\nv9+UeM79VX4k5Q==\n-----END PRIVATE KEY-----\n"
  end

  def other_valid_public_key do
    "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAN0Mhw3A4JqMERW8ObFDLBYOMnmIDo3BJo9h8OYGlahXeCt1rvoNNHnN\no3lRy6nasZR4CE+brZHU9qq9Nukoyy6+qBddidwQ3Sh3T98GqCh8IEWh0F84i8ZA\noVXURCS+s4I/SbA7JjiS3zvwjUklk55fGm90jEArzF+JUH2LsSGFAgMBAAE=\n-----END RSA PUBLIC KEY-----\n"
  end

  def invalid_private_key do
    "-----BEGIN PRIVATE KEY-----\nMIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKuqTgsv4Czpl+vP\n2jdUxK3mbx5M4h/QYAjHm3PaVrlyChNhI+ytnG/9eToynsd6g15Th+1PknNeUhth\nwJIReW/tcobhVs+QEW4z/9lzdWK2jS+9/a5YCgEl7qgQ++cZyNDdsv7na38hxAFf\n9UHA9taFKot8y7CFL1o69hXJb22LAgMBAAECgYAxPnmE3AcC2z+pdcazeK2y9ReL\nKaL0XWIvIpOFeGzIZd5eEM+tZWArABt2hm7l6k8lD/E+MkVgsv36vN/xBvI+oSQp\ns/e/rQ/TXTc8kg93inn576/zlrbn4HBo6hbGKP5xQgJfsSXSga1ZFz66ohbmsUVQ\nXiMhUGaW31S66P7TgQJBANVdl3l5/rEQUO/mN2CoRIdcg3a9FcC+TGFec3bHNE/L\nW9fAZueYk8QXz8PWumE+DzyANJKIXpPcoft2+UzSig0CQQDN95e111HJOVHQQ/wl\nX9VHkjg9GHaDG8sb0TjRHSovrHykgl3HiaoetaIv8rX8yW9euZF5yw/hF8uO3Kgs\nhWf3AkEAv9RXnaXrMPKEcku/Oi3O/wxUPesepZ3yOhCbKw1KoPsq5b1cR5jMMZ9e\n8qoaA9eyBykVGzF0JuhU0itTVJht+QJBALMLCfxuwo/TngUXNDchCXv/5Zdmjo8G\nOBdkVqmhWqy6mlc/ZFoyl4m+htB7givOx1tmoMlo9dLMJo13z1F0Xp0CQBqkDWdb\n9CTHG8PEwP2vlpj0XLubruft3w/2/jmiopt/O3HsV4HPSxcqtcbiFiE0oyTiYNqj\nDNSf2gX2ByEKHwY=\n-----END PRIVATE KEY-----\n\n"
  end
end
