defmodule Boruta.Oauth.AuthorizeResponseTest do
  use ExUnit.Case

  alias Boruta.Oauth.AuthorizeResponse

  describe "redirect_to_url/1" do
    test "returns an url with access_token type" do
      response = %AuthorizeResponse{
        type: :token,
        access_token: "value",
        expires_in: 10,
        redirect_uri: "http://redirect.uri"
      }

      assert AuthorizeResponse.redirect_to_url(response) ==
               "http://redirect.uri#access_token=value&expires_in=10"
    end

    test "returns a fragment according to `response_mode` for hybrid requests" do
      response = %AuthorizeResponse{
        type: :hybrid,
        code: "value",
        access_token: "value",
        expires_in: 10,
        redirect_uri: "http://redirect.uri",
        response_mode: "fragment"
      }

      assert AuthorizeResponse.redirect_to_url(response) ==
               "http://redirect.uri#access_token=value&code=value&expires_in=10"
    end

    test "returns query params according to `response_mode` for hybrid requests" do
      response = %AuthorizeResponse{
        type: :hybrid,
        code: "value",
        access_token: "value",
        expires_in: 10,
        redirect_uri: "http://redirect.uri",
        response_mode: "query"
      }

      assert AuthorizeResponse.redirect_to_url(response) ==
               "http://redirect.uri?access_token=value&code=value&expires_in=10"
    end

    test "returns an url with access_token type and a state" do
      response = %AuthorizeResponse{
        type: :token,
        access_token: "value",
        expires_in: 10,
        state: "state",
        redirect_uri: "http://redirect.uri"
      }

      assert AuthorizeResponse.redirect_to_url(response) ==
               "http://redirect.uri#access_token=value&expires_in=10&state=state"
    end

    test "returns an url with hybrid type" do
      response = %AuthorizeResponse{
        type: :hybrid,
        access_token: "access_token",
        id_token: "id_token",
        expires_in: 10,
        redirect_uri: "http://redirect.uri"
      }

      assert AuthorizeResponse.redirect_to_url(response) ==
               "http://redirect.uri#access_token=access_token&expires_in=10&id_token=id_token"
    end

    test "returns an url with hybrid type, a state and a token_type" do
      response = %AuthorizeResponse{
        type: :hybrid,
        access_token: "access_token",
        id_token: "id_token",
        expires_in: 10,
        state: "state",
        redirect_uri: "http://redirect.uri",
        token_type: "token_type"
      }

      assert AuthorizeResponse.redirect_to_url(response) ==
               "http://redirect.uri#access_token=access_token&expires_in=10&id_token=id_token&state=state&token_type=token_type"
    end

    test "returns an url with code type" do
      response = %AuthorizeResponse{
        type: :code,
        code: "value",
        redirect_uri: "http://redirect.uri"
      }

      assert AuthorizeResponse.redirect_to_url(response) == "http://redirect.uri?code=value"
    end

    test "returns an url with code type and a state" do
      response = %AuthorizeResponse{
        type: :code,
        code: "value",
        state: "state",
        redirect_uri: "http://redirect.uri"
      }

      assert AuthorizeResponse.redirect_to_url(response) ==
               "http://redirect.uri?code=value&state=state"
    end

    test "returns an url with a query in redirect_uri" do
      response = %AuthorizeResponse{
        type: :code,
        code: "value",
        state: "state",
        redirect_uri: "http://redirect.uri?foo=bar"
      }

      assert AuthorizeResponse.redirect_to_url(response) ==
               "http://redirect.uri?code=value&state=state&foo=bar"
    end

    test "returns query params according to `response_mode` for code requests" do
      response = %AuthorizeResponse{
        type: :code,
        code: "value",
        state: "state",
        redirect_uri: "http://redirect.uri",
        response_mode: "query"
      }

      assert AuthorizeResponse.redirect_to_url(response) ==
               "http://redirect.uri?code=value&state=state"
    end

    test "returns fragment according to `response_mode` for token requests" do
      response = %AuthorizeResponse{
        type: :token,
        access_token: "value",
        expires_in: 10,
        redirect_uri: "http://redirect.uri",
        response_mode: "fragment"
      }

      assert AuthorizeResponse.redirect_to_url(response) ==
               "http://redirect.uri#access_token=value&expires_in=10"
    end
  end
end
