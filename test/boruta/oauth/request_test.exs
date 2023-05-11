defmodule Boruta.Oauth.RequestTest do
  use ExUnit.Case

  use Plug.Test

  defmodule Token do
    @moduledoc false

    use Joken.Config, default_signer: :pem_rs512
  end

  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.IntrospectRequest
  alias Boruta.Oauth.Request
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.RevokeRequest
  alias Boruta.Oauth.TokenRequest

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

      assert {:error, %Error{error: :invalid_request, error_description: "Unsigned request jwt param is malformed."}} =
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

      assert {:error, %Error{error: :invalid_request, error_description: "Unsigned request jwt param is malformed."}} =
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
    setup do
      bypass = Bypass.open()

      {:ok, bypass: bypass}
    end

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

    test "returns an error if cannot fetch (token endpoint)", %{bypass: bypass} do
      request_uri = "http://localhost:#{bypass.port}/request"

      Bypass.expect_once(bypass, "GET", "/request", fn conn ->
        Plug.Conn.resp(conn, 400, "")
      end)

      conn =
        conn(:post, "/", %{
          "request_uri" => request_uri
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not fetch unsigned request parameter from given URI."
              }} = Request.token_request(conn)
    end

    test "returns an error with bad jwt (token endpoint)", %{bypass: bypass} do
      request_uri = "http://localhost:#{bypass.port}/request"

      Bypass.expect_once(bypass, "GET", "/request", fn conn ->
        Plug.Conn.resp(conn, 200, "bad_jwt")
      end)

      conn =
        conn(:post, "/", %{
          "request_uri" => request_uri
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not fetch unsigned request parameter from given URI."
              }} = Request.token_request(conn)
    end

    test "parse unsigned request (token endpoint)", %{bypass: bypass} do
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

      request_uri = "http://localhost:#{bypass.port}/request"

      Bypass.expect_once(bypass, "GET", "/request", fn conn ->
        Plug.Conn.resp(conn, 200, request)
      end)

      conn =
        conn(:post, "/", %{
          "request_uri" => request_uri
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

    test "returns an error if cannot fetch (authorize endpoint)", %{bypass: bypass} do
      request_uri = "http://localhost:#{bypass.port}/request"

      Bypass.expect_once(bypass, "GET", "/request", fn conn ->
        Plug.Conn.resp(conn, 400, "")
      end)

      conn =
        conn(:get, "/", %{
          "request_uri" => request_uri
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not fetch unsigned request parameter from given URI."
              }} = Request.authorize_request(conn, %ResourceOwner{sub: "sub"})
    end

    test "returns an error with bad jwt (authorize endpoint)", %{bypass: bypass} do
      request_uri = "http://localhost:#{bypass.port}/request"

      Bypass.expect_once(bypass, "GET", "/request", fn conn ->
        Plug.Conn.resp(conn, 200, "bad_jwt")
      end)

      conn =
        conn(:get, "/", %{
          "request_uri" => request_uri
        })

      assert {:error,
              %Error{
                error: :invalid_request,
                error_description: "Could not fetch unsigned request parameter from given URI."
              }} = Request.authorize_request(conn, %ResourceOwner{sub: "sub"})
    end

    test "parse unsigned request (authorize endpoint)", %{bypass: bypass} do
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

      request_uri = "http://localhost:#{bypass.port}/request"

      Bypass.expect_once(bypass, "GET", "/request", fn conn ->
        Plug.Conn.resp(conn, 200, request)
      end)

      conn =
        conn(:get, "/", %{
          "request_uri" => request_uri
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
end
