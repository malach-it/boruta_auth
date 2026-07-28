defmodule Boruta.Oauth.RequestTest do
  use Boruta.DataCase

  import Plug.Test
  import Boruta.Factory

  defmodule Token do
    @moduledoc false

    use Joken.Config, default_signer: :pem_rs512
  end

  alias Boruta.Oauth.AuthorizationCodeRequest
  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.IntrospectRequest
  alias Boruta.Oauth.PreauthorizationCodeRequest
  alias Boruta.Oauth.PreauthorizedCodeRequest
  alias Boruta.Oauth.RefreshTokenRequest
  alias Boruta.Oauth.Request
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.RevokeRequest
  alias Boruta.Oauth.TokenRequest
  alias Boruta.Support.TLSServer

  describe "Basic client authentication (token endpoint)" do
    test "returns an error with bad basic header" do
      conn =
        conn(:post, "/", %{
          "grant_type" => "client_credentials"
        })
        |> Plug.Conn.put_req_header("authorization", "bad basic header")

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "`bad basic header` is not a valid Basic authorization header."
              }} = Request.token_request(conn)
    end

    test "adds client_authentication to the request" do
      client_id = SecureRandom.uuid()
      client_secret = "client_secret"

      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client_id, client_secret)

      conn =
        conn(:post, "/", %{
          "grant_type" => "client_credentials"
        })
        |> Plug.Conn.put_req_header("authorization", authorization_header)

      assert {:ok,
              %ClientCredentialsRequest{
                client_authentication: %{type: "basic", value: ^client_secret}
              }} = Request.token_request(conn)
    end
  end

  describe "Basic client authentication (introspect endpoint)" do
    test "returns an error with bad basic header" do
      conn =
        conn(:post, "/", %{
          "token" => "access_token"
        })
        |> Plug.Conn.put_req_header("authorization", "bad basic header")

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "`bad basic header` is not a valid Basic authorization header."
              }} = Request.introspect_request(conn)
    end

    test "adds client_authentication to the request" do
      client_id = SecureRandom.uuid()
      client_secret = "client_secret"

      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client_id, client_secret)

      conn =
        conn(:post, "/", %{
          "token" => "access_token"
        })
        |> Plug.Conn.put_req_header("authorization", authorization_header)

      assert {:ok,
              %IntrospectRequest{
                client_authentication: %{type: "basic", value: ^client_secret}
              }} = Request.introspect_request(conn)
    end
  end

  describe "Basic client authentication (revoke endpoint)" do
    test "returns an error with bad basic header" do
      conn =
        conn(:post, "/", %{
          "token" => "access_token"
        })
        |> Plug.Conn.put_req_header("authorization", "bad basic header")

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "`bad basic header` is not a valid Basic authorization header."
              }} = Request.revoke_request(conn)
    end

    test "adds client_authentication to the request" do
      client_id = SecureRandom.uuid()
      client_secret = "client_secret"

      %{req_headers: [{"authorization", authorization_header}]} =
        using_basic_auth(client_id, client_secret)

      conn =
        conn(:post, "/", %{
          "token" => "access_token"
        })
        |> Plug.Conn.put_req_header("authorization", authorization_header)

      assert {:ok,
              %RevokeRequest{
                client_authentication: %{type: "basic", value: ^client_secret}
              }} = Request.revoke_request(conn)
    end
  end

  describe "POST client authentication (token endpoint)" do
    test "adds client_authentication to the request" do
      client_secret = "client_secret"

      conn =
        conn(:post, "/", %{
          "grant_type" => "client_credentials",
          "client_id" => SecureRandom.uuid(),
          "client_secret" => client_secret
        })

      assert {:ok,
              %ClientCredentialsRequest{
                client_authentication: %{type: "post", value: ^client_secret}
              }} = Request.token_request(conn)
    end

    test "adds client_authentication to the request with no secret" do
      conn =
        conn(:post, "/", %{
          "grant_type" => "client_credentials",
          "client_id" => SecureRandom.uuid()
        })

      assert {:ok,
              %ClientCredentialsRequest{
                client_authentication: %{type: "post", value: nil}
              }} = Request.token_request(conn)
    end
  end

  describe "resource indicator request params" do
    test "adds resource to client credentials requests" do
      client_id = SecureRandom.uuid()
      resource = "https://mcp.example.com"

      conn =
        conn(:post, "/", %{
          "grant_type" => "client_credentials",
          "client_id" => client_id,
          "resource" => resource
        })

      assert {:ok, %ClientCredentialsRequest{resource: ^resource}} = Request.token_request(conn)
    end

    test "adds resource to authorization code token requests" do
      client_id = SecureRandom.uuid()
      resource = "https://mcp.example.com"

      conn =
        conn(:post, "/", %{
          "grant_type" => "authorization_code",
          "client_id" => client_id,
          "code" => "code",
          "resource" => resource
        })

      assert {:ok, %AuthorizationCodeRequest{resource: ^resource}} = Request.token_request(conn)
    end

    test "adds resource to refresh token requests" do
      resource = "https://mcp.example.com"

      conn =
        conn(:post, "/", %{
          "grant_type" => "refresh_token",
          "refresh_token" => "refresh_token",
          "resource" => resource
        })

      assert {:ok, %RefreshTokenRequest{resource: ^resource}} = Request.token_request(conn)
    end

    test "adds resource to preauthorized code token requests" do
      resource = "https://mcp.example.com"

      conn =
        conn(:post, "/", %{
          "grant_type" => "urn:ietf:params:oauth:grant-type:pre-authorized_code",
          "pre-authorized_code" => "code",
          "resource" => resource
        })

      assert {:ok, %PreauthorizationCodeRequest{resource: ^resource}} =
               Request.token_request(conn)
    end

    test "adds resource to authorization requests" do
      client_id = SecureRandom.uuid()
      redirect_uri = "https://redirect.uri"
      resource = "https://mcp.example.com"

      conn =
        conn(:get, "/", %{
          "response_type" => "code",
          "client_id" => client_id,
          "redirect_uri" => redirect_uri,
          "resource" => resource
        })

      assert {:ok, %CodeRequest{resource: ^resource}} =
               Request.authorize_request(conn, %ResourceOwner{sub: "sub"})
    end

    test "adds resource to preauthorized code authorization requests" do
      client_id = SecureRandom.uuid()
      redirect_uri = "https://redirect.uri"
      resource = "https://mcp.example.com"

      conn =
        conn(:get, "/", %{
          "response_type" => "urn:ietf:params:oauth:response-type:pre-authorized_code",
          "client_id" => client_id,
          "redirect_uri" => redirect_uri,
          "resource" => resource
        })

      assert {:ok, %PreauthorizedCodeRequest{resource: ^resource}} =
               Request.authorize_request(conn, %ResourceOwner{sub: "sub"})
    end
  end

  describe "POST client authentication (introspect endpoint)" do
    test "adds client_authentication to the request" do
      client_secret = "client_secret"

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_id" => SecureRandom.uuid(),
          "client_secret" => client_secret
        })

      assert {:ok,
              %IntrospectRequest{
                client_authentication: %{type: "post", value: ^client_secret}
              }} = Request.introspect_request(conn)
    end

    test "adds client_authentication to the request with no secret" do
      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_id" => SecureRandom.uuid()
        })

      assert {:ok,
              %IntrospectRequest{
                client_authentication: %{type: "post", value: nil}
              }} = Request.introspect_request(conn)
    end
  end

  describe "POST client authentication (revoke endpoint)" do
    test "adds client_authentication to the request" do
      client_secret = "client_secret"

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_id" => SecureRandom.uuid(),
          "client_secret" => client_secret
        })

      assert {:ok,
              %RevokeRequest{
                client_authentication: %{type: "post", value: ^client_secret}
              }} = Request.revoke_request(conn)
    end

    test "adds client_authentication to the request with no secret" do
      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_id" => SecureRandom.uuid()
        })

      assert {:ok,
              %RevokeRequest{
                client_authentication: %{type: "post", value: nil}
              }} = Request.revoke_request(conn)
    end
  end

  describe "JWT profile client authentication and authorization grants (token endpoint)" do
    test "returns an error with a bad JWT" do
      conn =
        conn(:post, "/", %{
          "grant_type" => "client_credentials",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => "bad jwt"
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not decode client assertion JWT."
              }} = Request.token_request(conn)
    end

    test "returns an error if client assertion does not contain iss claim" do
      signer = Joken.Signer.create("HS512", "my secret")
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)

      conn =
        conn(:post, "/", %{
          "grant_type" => "client_credentials",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Client assertion iss claim not found in client assertion JWT."
              }} = Request.token_request(conn)
    end

    test "returns an error if client assertion does not contain aud claim" do
      signer = Joken.Signer.create("HS512", "my secret")
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{"iss" => "issuer"}, signer)

      conn =
        conn(:post, "/", %{
          "grant_type" => "client_credentials",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Client assertion aud claim not found in client assertion JWT."
              }} = Request.token_request(conn)
    end

    test "returns an error if client assertion aud claim does does not match server issuer" do
      signer = Joken.Signer.create("HS512", "my secret")

      {:ok, client_assertion, _claims} =
        Token.encode_and_sign(%{"iss" => "issuer", "aud" => "bad audience"}, signer)

      conn =
        conn(:post, "/", %{
          "grant_type" => "client_credentials",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description:
                  "Client assertion aud claim does not match with authorization server (boruta)."
              }} = Request.token_request(conn)
    end

    test "returns an error if client assertion does not contain exp claim" do
      signer = Joken.Signer.create("HS512", "my secret")

      {:ok, client_assertion, _claims} =
        Token.encode_and_sign(%{"iss" => "issuer", "aud" => "boruta"}, signer)

      conn =
        conn(:post, "/", %{
          "grant_type" => "client_credentials",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Client assertion exp claim not found in client assertion JWT."
              }} = Request.token_request(conn)
    end

    test "adds client_id to the request" do
      client_id = SecureRandom.uuid()
      signer = Joken.Signer.create("HS512", "my secret")

      {:ok, client_assertion, _claims} =
        Token.encode_and_sign(
          %{
            "aud" => "boruta",
            "iss" => "issuer",
            "sub" => client_id,
            "exp" => DateTime.utc_now() |> DateTime.to_unix()
          },
          signer
        )

      conn =
        conn(:post, "/", %{
          "grant_type" => "client_credentials",
          "client_secret" => "secret",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:ok, %ClientCredentialsRequest{client_id: ^client_id}} = Request.token_request(conn)
    end

    test "adds client_authentication to the request" do
      client_id = SecureRandom.uuid()
      signer = Joken.Signer.create("HS512", "my secret")

      {:ok, client_assertion, _claims} =
        Token.encode_and_sign(
          %{
            "aud" => "boruta",
            "iss" => "issuer",
            "sub" => client_id,
            "exp" => DateTime.utc_now() |> DateTime.to_unix()
          },
          signer
        )

      conn =
        conn(:post, "/", %{
          "grant_type" => "client_credentials",
          "client_secret" => "secret",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:ok,
              %ClientCredentialsRequest{
                client_authentication: %{type: "jwt", value: ^client_assertion}
              }} = Request.token_request(conn)
    end
  end

  describe "JWT profile client authentication and authorization grants (introspect endpoint)" do
    test "returns an error with a bad JWT" do
      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => "bad jwt"
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not decode client assertion JWT."
              }} = Request.introspect_request(conn)
    end

    test "returns an error if client assertion does not contain iss claim" do
      signer = Joken.Signer.create("HS512", "my secret")
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Client assertion iss claim not found in client assertion JWT."
              }} = Request.introspect_request(conn)
    end

    test "returns an error if client assertion does not contain aud claim" do
      signer = Joken.Signer.create("HS512", "my secret")
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{"iss" => "issuer"}, signer)

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Client assertion aud claim not found in client assertion JWT."
              }} = Request.introspect_request(conn)
    end

    test "returns an error if client assertion aud claim does does not match server issuer" do
      signer = Joken.Signer.create("HS512", "my secret")

      {:ok, client_assertion, _claims} =
        Token.encode_and_sign(%{"iss" => "issuer", "aud" => "bad audience"}, signer)

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description:
                  "Client assertion aud claim does not match with authorization server (boruta)."
              }} = Request.introspect_request(conn)
    end

    test "returns an error if client assertion does not contain exp claim" do
      signer = Joken.Signer.create("HS512", "my secret")

      {:ok, client_assertion, _claims} =
        Token.encode_and_sign(%{"iss" => "issuer", "aud" => "boruta"}, signer)

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Client assertion exp claim not found in client assertion JWT."
              }} = Request.introspect_request(conn)
    end

    test "adds client_id to the request" do
      client_id = SecureRandom.uuid()
      signer = Joken.Signer.create("HS512", "my secret")

      {:ok, client_assertion, _claims} =
        Token.encode_and_sign(
          %{
            "aud" => "boruta",
            "iss" => "issuer",
            "sub" => client_id,
            "exp" => DateTime.utc_now() |> DateTime.to_unix()
          },
          signer
        )

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_secret" => "secret",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:ok, %IntrospectRequest{client_id: ^client_id}} = Request.introspect_request(conn)
    end

    test "adds client_authentication to the request" do
      client_id = SecureRandom.uuid()
      signer = Joken.Signer.create("HS512", "my secret")

      {:ok, client_assertion, _claims} =
        Token.encode_and_sign(
          %{
            "aud" => "boruta",
            "iss" => "issuer",
            "sub" => client_id,
            "exp" => DateTime.utc_now() |> DateTime.to_unix()
          },
          signer
        )

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_secret" => "secret",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:ok,
              %IntrospectRequest{
                client_authentication: %{type: "jwt", value: ^client_assertion}
              }} = Request.introspect_request(conn)
    end
  end

  describe "JWT profile client authentication and authorization grants (revoke endpoint)" do
    test "returns an error with a bad JWT" do
      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => "bad jwt"
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not decode client assertion JWT."
              }} = Request.revoke_request(conn)
    end

    test "returns an error if client assertion does not contain iss claim" do
      signer = Joken.Signer.create("HS512", "my secret")
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{}, signer)

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Client assertion iss claim not found in client assertion JWT."
              }} = Request.revoke_request(conn)
    end

    test "returns an error if client assertion does not contain aud claim" do
      signer = Joken.Signer.create("HS512", "my secret")
      {:ok, client_assertion, _claims} = Token.encode_and_sign(%{"iss" => "issuer"}, signer)

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Client assertion aud claim not found in client assertion JWT."
              }} = Request.revoke_request(conn)
    end

    test "returns an error if client assertion aud claim does does not match server issuer" do
      signer = Joken.Signer.create("HS512", "my secret")

      {:ok, client_assertion, _claims} =
        Token.encode_and_sign(%{"iss" => "issuer", "aud" => "bad audience"}, signer)

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description:
                  "Client assertion aud claim does not match with authorization server (boruta)."
              }} = Request.revoke_request(conn)
    end

    test "returns an error if client assertion does not contain exp claim" do
      signer = Joken.Signer.create("HS512", "my secret")

      {:ok, client_assertion, _claims} =
        Token.encode_and_sign(%{"iss" => "issuer", "aud" => "boruta"}, signer)

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Client assertion exp claim not found in client assertion JWT."
              }} = Request.revoke_request(conn)
    end

    test "adds client_id to the request" do
      client_id = SecureRandom.uuid()
      signer = Joken.Signer.create("HS512", "my secret")

      {:ok, client_assertion, _claims} =
        Token.encode_and_sign(
          %{
            "aud" => "boruta",
            "iss" => "issuer",
            "sub" => client_id,
            "exp" => DateTime.utc_now() |> DateTime.to_unix()
          },
          signer
        )

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_secret" => "secret",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:ok, %RevokeRequest{client_id: ^client_id}} = Request.revoke_request(conn)
    end

    test "adds client_authentication to the request" do
      client_id = SecureRandom.uuid()
      signer = Joken.Signer.create("HS512", "my secret")

      {:ok, client_assertion, _claims} =
        Token.encode_and_sign(
          %{
            "aud" => "boruta",
            "iss" => "issuer",
            "sub" => client_id,
            "exp" => DateTime.utc_now() |> DateTime.to_unix()
          },
          signer
        )

      conn =
        conn(:post, "/", %{
          "token" => "access_token",
          "client_secret" => "secret",
          "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion" => client_assertion
        })

      assert {:ok,
              %RevokeRequest{
                client_authentication: %{type: "jwt", value: ^client_assertion}
              }} = Request.revoke_request(conn)
    end
  end

  describe "unsigned requests" do
    test "returns an error with bad jwt (token endpoint)" do
      conn =
        conn(:post, "/", %{
          "request" => "bad_jwt"
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Unsigned request jwt param is malformed."
              }} =
               Request.token_request(conn)
    end

    test "parse unsigned request (token endpoint)" do
      signer = Joken.Signer.create("HS512", "my secret")

      client_id = SecureRandom.uuid()

      {:ok, request, _claims} =
        Token.encode_and_sign(
          %{
            "client_id" => client_id,
            "grant_type" => "client_credentials"
          },
          signer
        )

      conn =
        conn(:post, "/", %{
          "request" => request
        })

      assert {:ok, %ClientCredentialsRequest{client_id: ^client_id}} = Request.token_request(conn)
    end

    test "returns an error with bad jwt (authorize endpoint)" do
      conn =
        conn(:get, "/", %{
          "request" => "bad_jwt"
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Unsigned request jwt param is malformed."
              }} =
               Request.authorize_request(conn, %ResourceOwner{sub: "sub"})
    end

    test "parse unsigned request (authorize endpoint)" do
      signer = Joken.Signer.create("HS512", "my secret")

      client_id = SecureRandom.uuid()
      redirect_uri = "http://redirect.uri"

      {:ok, request, _claims} =
        Token.encode_and_sign(
          %{
            "client_id" => client_id,
            "response_type" => "token",
            "redirect_uri" => redirect_uri
          },
          signer
        )

      conn =
        conn(:get, "/", %{
          "request" => request
        })

      assert {:ok,
              %TokenRequest{
                client_id: ^client_id,
                redirect_uri: ^redirect_uri
              }} = Request.authorize_request(conn, %ResourceOwner{sub: "sub"})
    end
  end

  describe "unsigned requests from uri" do
    test "returns an error with malformed uri (token endpoint)" do
      conn =
        conn(:post, "/", %{
          "request_uri" => "bad_uri"
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not fetch unsigned request parameter from given URI."
              }} = Request.token_request(conn)
    end

    test "returns an OAuth error without trusted hosts or authorities" do
      conn =
        conn(:post, "/", %{
          "request_uri" => "https://request.example.com/request"
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description:
                  "Client must configure trusted hosts or authorities for outbound requests."
              }} = Request.token_request(conn)
    end

    test "returns an error if cannot fetch (token endpoint)" do
      server = start_tls_server("", status: 400)

      client =
        insert(:client,
          trusted_authorities: server.trusted_authorities,
          trusted_hosts: ["localhost"]
        )

      conn =
        conn(:post, "/", %{
          "client_id" => client.id,
          "request_uri" => "#{server.url}/request"
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not fetch unsigned request parameter from given URI."
              }} = Request.token_request(conn)
    end

    test "returns an error with bad jwt (token endpoint)" do
      server = start_tls_server("bad_jwt")

      client =
        insert(:client,
          trusted_authorities: server.trusted_authorities,
          trusted_hosts: ["localhost"]
        )

      conn =
        conn(:post, "/", %{
          "client_id" => client.id,
          "request_uri" => "#{server.url}/request"
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not fetch unsigned request parameter from given URI."
              }} = Request.token_request(conn)
    end

    test "parse unsigned request (token endpoint)" do
      signer = Joken.Signer.create("HS512", "my secret")
      client_id = SecureRandom.uuid()

      {:ok, request, _claims} =
        Token.encode_and_sign(
          %{
            "client_id" => client_id,
            "grant_type" => "client_credentials"
          },
          signer
        )

      server = start_tls_server(request)

      insert(:client,
        id: client_id,
        trusted_authorities: server.trusted_authorities,
        trusted_hosts: ["localhost"]
      )

      conn =
        conn(:post, "/", %{
          "client_id" => client_id,
          "request_uri" => "#{server.url}/request"
        })

      assert {:ok, %ClientCredentialsRequest{client_id: ^client_id}} = Request.token_request(conn)
    end

    test "returns an error with malformed uri (authorize endpoint)" do
      conn =
        conn(:post, "/", %{
          "request_uri" => "bad_uri"
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not fetch unsigned request parameter from given URI."
              }} = Request.authorize_request(conn, %ResourceOwner{sub: "sub"})
    end

    test "returns an error if cannot fetch (authorize endpoint)" do
      server = start_tls_server("", status: 400)

      client =
        insert(:client,
          trusted_authorities: server.trusted_authorities,
          trusted_hosts: ["localhost"]
        )

      conn =
        conn(:get, "/", %{
          "client_id" => client.id,
          "request_uri" => "#{server.url}/request"
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not fetch unsigned request parameter from given URI."
              }} = Request.authorize_request(conn, %ResourceOwner{sub: "sub"})
    end

    test "returns an error with bad jwt (authorize endpoint)" do
      server = start_tls_server("bad_jwt")

      client =
        insert(:client,
          trusted_authorities: server.trusted_authorities,
          trusted_hosts: ["localhost"]
        )

      conn =
        conn(:get, "/", %{
          "client_id" => client.id,
          "request_uri" => "#{server.url}/request"
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not fetch unsigned request parameter from given URI."
              }} = Request.authorize_request(conn, %ResourceOwner{sub: "sub"})
    end

    test "parse unsigned request (authorize endpoint)" do
      signer = Joken.Signer.create("HS512", "my secret")
      client_id = SecureRandom.uuid()
      redirect_uri = "http://redirect.uri"

      {:ok, request, _claims} =
        Token.encode_and_sign(
          %{
            "client_id" => client_id,
            "response_type" => "token",
            "redirect_uri" => redirect_uri
          },
          signer
        )

      server = start_tls_server(request)

      insert(:client,
        id: client_id,
        trusted_authorities: server.trusted_authorities,
        trusted_hosts: ["localhost"]
      )

      conn =
        conn(:get, "/", %{
          "client_id" => client_id,
          "request_uri" => "#{server.url}/request"
        })

      assert {:ok,
              %TokenRequest{
                client_id: ^client_id,
                redirect_uri: ^redirect_uri
              }} = Request.authorize_request(conn, %ResourceOwner{sub: "sub"})
    end
  end

  defp using_basic_auth(username, password) do
    authorization_header = "Basic " <> Base.encode64("#{username}:#{password}")
    %{req_headers: [{"authorization", authorization_header}]}
  end

  defp start_tls_server(body, opts \\ []) do
    {:ok, server} = TLSServer.start(body, opts)

    on_exit(fn ->
      TLSServer.stop(server)
    end)

    server
  end
end
