defmodule Boruta.Oauth.RequestTest do
  use ExUnit.Case

  use Plug.Test

  alias Boruta.Oauth.ClientCredentialsRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Request

  defmodule Token do
    @moduledoc false

    use Joken.Config, default_signer: :pem_rs512
  end

  describe "JWT profile client authentication and authorization grants" do
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
  end
end
