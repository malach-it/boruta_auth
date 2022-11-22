defmodule Boruta.Oauth.RequestTest do
  use ExUnit.Case

  use Plug.Test

  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.IntrospectRequest
  alias Boruta.Oauth.Request
  alias Boruta.Oauth.RevokeRequest

  defmodule Token do
    @moduledoc false

    use Joken.Config, default_signer: :pem_rs512
  end

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

  defp using_basic_auth(username, password) do
    authorization_header = "Basic " <> Base.encode64("#{username}:#{password}")
    %{req_headers: [{"authorization", authorization_header}]}
  end
end
