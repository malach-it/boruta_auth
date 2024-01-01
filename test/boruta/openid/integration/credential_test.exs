defmodule Boruta.OpenidTest.CredentialTest do
  use Boruta.DataCase

  import Boruta.Factory
  import Plug.Conn

  alias Boruta.Ecto.Token
  alias Boruta.Oauth.Error
  alias Boruta.Openid
  alias Boruta.Openid.ApplicationMock
  alias Boruta.Openid.CredentialResponse

  describe "deliver verifiable credentials" do
    test "returns an error with no access token" do
      conn = %Plug.Conn{}

      assert {:credential_failure,
              %Boruta.Oauth.Error{
                error: :invalid_request,
                error_description: "Invalid bearer from Authorization header.",
                status: :bad_request
              }} = Openid.credential(conn, %{}, ApplicationMock)
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
              }} = Openid.credential(conn, %{}, ApplicationMock)
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
              }} = Openid.credential(conn, %{}, ApplicationMock)
    end

    test "returns an error with a valid bearer" do
      credential_params = %{}
      %Token{value: access_token} = insert(:token)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert Openid.credential(conn, credential_params, ApplicationMock) ==
               {:credential_failure,
                %Error{
                  status: :bad_request,
                  error: :invalid_request,
                  error_description:
                    "Request body validation failed. Required property credential_identifier is missing at #."
                }}
    end

    test "returns an error with an invalid credential_identifier" do
      credential_params = %{"credential_identifier" => "bad identifier"}
      %Token{value: access_token} = insert(:token)

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert Openid.credential(conn, credential_params, ApplicationMock) ==
               {:credential_failure,
                %Error{
                  status: :bad_request,
                  error: :invalid_request,
                  error_description: "Invalid credential identifier."
                }}
    end

    test "returns a credential with a valid credential_identifier" do
      credential_params = %{"credential_identifier" => "identifier"}

      %Token{value: access_token} =
        insert(:token, authorization_details: [%{"credential_identifiers" => ["identifier"]}])

      conn =
        %Plug.Conn{}
        |> put_req_header("authorization", "Bearer #{access_token}")

      assert Openid.credential(conn, credential_params, ApplicationMock) ==
               {:credential_created,
                %CredentialResponse{
                  format: "jwt_vc_json",
                  credential: ""
                }}
    end
  end
end
