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

    test "returns an url with code type" do
      response = %AuthorizeResponse{
        type: :code,
        code: "value",
        expires_in: 10,
        redirect_uri: "http://redirect.uri"
      }

      assert AuthorizeResponse.redirect_to_url(response) == "http://redirect.uri?code=value"
    end

    test "returns an url with code type and a state" do
      response = %AuthorizeResponse{
        type: :code,
        code: "value",
        expires_in: 10,
        state: "state",
        redirect_uri: "http://redirect.uri"
      }

      assert AuthorizeResponse.redirect_to_url(response) ==
               "http://redirect.uri?code=value&state=state"
    end
  end
end
