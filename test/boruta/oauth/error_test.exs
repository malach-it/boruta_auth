defmodule Boruta.Oauth.ErrorTest do
  use ExUnit.Case

  alias Boruta.Oauth.Error

  describe "with_format/2" do
    test "returns error with nil format when client is invalid" do
      assert %Error{format: nil, redirect_uri: nil} =
               Error.with_format(
                 %Error{
                   status: :bad_request,
                   error: :invalid_client,
                   error_description: "error_description"
                 },
                 %{}
               )
    end
  end

  describe "redirect_to_url/1" do
    test "returns empty string" do
      error = %Error{
        status: :bad_request,
        error: "error",
        error_description: "Error description"
      }

      assert Error.redirect_to_url(error) == ""
    end

    test "returns an url with fragment" do
      error = %Error{
        status: :bad_request,
        format: :fragment,
        error: "error",
        error_description: "Error description",
        redirect_uri: "http://redirect.uri"
      }

      assert Error.redirect_to_url(error) ==
               "http://redirect.uri#error=error&error_description=Error+description"
    end

    test "returns an url with query" do
      error = %Error{
        status: :bad_request,
        format: :query,
        error: "error",
        error_description: "Error description",
        redirect_uri: "http://redirect.uri"
      }

      assert Error.redirect_to_url(error) ==
               "http://redirect.uri?error=error&error_description=Error+description"
    end

    test "returns an url with fragment with a state" do
      error = %Error{
        status: :bad_request,
        format: :fragment,
        error: "error",
        error_description: "Error description",
        redirect_uri: "http://redirect.uri",
        state: "state"
      }

      assert Error.redirect_to_url(error) ==
               "http://redirect.uri#error=error&error_description=Error+description&state=state"
    end

    test "returns an url with query with a state" do
      error = %Error{
        status: :bad_request,
        format: :query,
        error: "error",
        error_description: "Error description",
        redirect_uri: "http://redirect.uri",
        state: "state"
      }

      assert Error.redirect_to_url(error) ==
               "http://redirect.uri?error=error&error_description=Error+description&state=state"
    end
  end
end
