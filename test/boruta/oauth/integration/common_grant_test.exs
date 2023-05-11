defmodule Boruta.OauthTest.CommonGrantTest do
  use ExUnit.Case

  alias Boruta.Oauth
  alias Boruta.Oauth.ApplicationMock
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner

  describe "token request" do
    test "returns an error without params" do
      assert Oauth.token(%Plug.Conn{body_params: %{}}, ApplicationMock) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request is not a valid OAuth request. Need a grant_type param.",
                  status: :bad_request
                }}
    end

    test "returns an error with empty params" do
      assert Oauth.token(%Plug.Conn{body_params: %{}}, ApplicationMock) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request is not a valid OAuth request. Need a grant_type param.",
                  status: :bad_request
                }}
    end

    test "returns an error with invalid grant_type" do
      assert Oauth.token(%Plug.Conn{body_params: %{"grant_type" => "boom"}}, ApplicationMock) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request body validation failed. #/grant_type do match required pattern /^(client_credentials|password|authorization_code|refresh_token)$/.",
                  status: :bad_request
                }}
    end

    test "returns an error with invalid grant_type (bad format)" do
      assert Oauth.token(%Plug.Conn{body_params: %{"grant_type" => nil}}, ApplicationMock) ==
               {:token_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request body validation failed. The type at #/grant_type `null` do not match the required types [\"string\"].",
                  status: :bad_request
                }}
    end
  end

  describe "authorize request" do
    test "returns an error without params" do
      assert Oauth.authorize(%Plug.Conn{query_params: %{}}, %ResourceOwner{sub: "sub"}, ApplicationMock) ==
               {:authorize_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request is not a valid OAuth request. Need a response_type param.",
                  status: :bad_request
                }}
    end

    test "returns an error with empty params" do
      assert Oauth.authorize(%Plug.Conn{query_params: %{}}, %ResourceOwner{sub: "sub"}, ApplicationMock) ==
               {:authorize_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Request is not a valid OAuth request. Need a response_type param.",
                  status: :bad_request
                }}
    end

    test "returns an error with invalid response_type" do
      assert Oauth.authorize(
               %Plug.Conn{query_params: %{"response_type" => "boom"}},
               %ResourceOwner{sub: "sub"},
               ApplicationMock
             ) ==
               {:authorize_error,
                %Error{
                  error: :invalid_request,
                  error_description:
                    "Invalid response_type param, may be on of `code` for Authorization Code request, `code id_token`, `code token`, `code id_token token` for Hybrid requests, or `token`, `id_token token` for Implicit requests.",
                  status: :bad_request
                }}
    end
  end
end
