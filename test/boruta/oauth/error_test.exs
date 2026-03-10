defmodule Boruta.Oauth.ErrorTest do
  use ExUnit.Case

  alias Boruta.Oauth.CodeRequest
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.HybridRequest
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.TokenRequest

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

    test "returns error with form_post format for code request with response_mode=form_post" do
      request = %CodeRequest{
        client_id: "client_id",
        redirect_uri: "http://redirect.uri",
        resource_owner: %ResourceOwner{sub: "sub"},
        state: "state",
        response_mode: "form_post"
      }

      error = %Error{
        status: :bad_request,
        error: :invalid_scope,
        error_description: "error_description"
      }

      assert %Error{format: :form_post, redirect_uri: "http://redirect.uri", state: "state"} =
               Error.with_format(error, request)
    end

    test "returns error with form_post format for token request with response_mode=form_post" do
      request = %TokenRequest{
        client_id: "client_id",
        redirect_uri: "http://redirect.uri",
        resource_owner: %ResourceOwner{sub: "sub"},
        state: "state",
        response_mode: "form_post"
      }

      error = %Error{
        status: :bad_request,
        error: :invalid_scope,
        error_description: "error_description"
      }

      assert %Error{format: :form_post, redirect_uri: "http://redirect.uri", state: "state"} =
               Error.with_format(error, request)
    end

    test "returns error with form_post format for hybrid request with response_mode=form_post" do
      request = %HybridRequest{
        client_id: "client_id",
        redirect_uri: "http://redirect.uri",
        resource_owner: %ResourceOwner{sub: "sub"},
        state: "state",
        response_mode: "form_post"
      }

      error = %Error{
        status: :bad_request,
        error: :invalid_scope,
        error_description: "error_description"
      }

      assert %Error{format: :form_post, redirect_uri: "http://redirect.uri", state: "state"} =
               Error.with_format(error, request)
    end

    test "returns error with query format for code request without response_mode" do
      request = %CodeRequest{
        client_id: "client_id",
        redirect_uri: "http://redirect.uri",
        resource_owner: %ResourceOwner{sub: "sub"},
        state: "state"
      }

      error = %Error{
        status: :bad_request,
        error: :invalid_scope,
        error_description: "error_description"
      }

      assert %Error{format: :query} = Error.with_format(error, request)
    end

    test "returns error with fragment format for token request without response_mode" do
      request = %TokenRequest{
        client_id: "client_id",
        redirect_uri: "http://redirect.uri",
        resource_owner: %ResourceOwner{sub: "sub"},
        state: "state"
      }

      error = %Error{
        status: :bad_request,
        error: :invalid_scope,
        error_description: "error_description"
      }

      assert %Error{format: :fragment} = Error.with_format(error, request)
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
