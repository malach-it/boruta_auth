defmodule Boruta.Oauth.ErrorTest do
  use ExUnit.Case

  alias Boruta.Oauth.Error

  describe "redirect_to_url/1" do
    test "returns empty string" do
      error = %Error{
        error: "error",
        error_description: "Error description"
      }

      assert Error.redirect_to_url(error) == ""
    end

    test "returns an url with fragment" do
      error = %Error{
        format: :fragment,
        error: "error",
        error_description: "Error description",
        redirect_uri: "http://redirect.uri"
      }

      assert Error.redirect_to_url(error) == "http://redirect.uri#error=error&error_description=Error+description"
    end

    test "returns an url with query" do
      error = %Error{
        format: :query,
        error: "error",
        error_description: "Error description",
        redirect_uri: "http://redirect.uri"
      }

      assert Error.redirect_to_url(error) == "http://redirect.uri?error=error&error_description=Error+description"
    end
  end
end
