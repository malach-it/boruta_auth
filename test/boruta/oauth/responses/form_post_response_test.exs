defmodule Boruta.Oauth.FormPostResponseTest do
  use ExUnit.Case

  alias Boruta.Oauth.FormPostResponse

  describe "params/1" do
    test "returns params map with code" do
      response = %FormPostResponse{
        redirect_uri: "http://redirect.uri",
        code: "authorization_code",
        state: "state_value",
        type: :code
      }

      assert FormPostResponse.params(response) == %{
               code: "authorization_code",
               state: "state_value"
             }
    end

    test "returns params map with access_token" do
      response = %FormPostResponse{
        redirect_uri: "http://redirect.uri",
        access_token: "access_token_value",
        token_type: "bearer",
        expires_in: 3600,
        state: "state_value",
        type: :token
      }

      assert FormPostResponse.params(response) == %{
               access_token: "access_token_value",
               token_type: "bearer",
               expires_in: 3600,
               state: "state_value"
             }
    end

    test "returns params map with id_token" do
      response = %FormPostResponse{
        redirect_uri: "http://redirect.uri",
        id_token: "id_token_value",
        state: "state_value",
        type: :token
      }

      assert FormPostResponse.params(response) == %{
               id_token: "id_token_value",
               state: "state_value"
             }
    end

    test "returns params map with hybrid response" do
      response = %FormPostResponse{
        redirect_uri: "http://redirect.uri",
        code: "authorization_code",
        access_token: "access_token_value",
        id_token: "id_token_value",
        token_type: "bearer",
        expires_in: 3600,
        state: "state_value",
        type: :hybrid
      }

      assert FormPostResponse.params(response) == %{
               code: "authorization_code",
               access_token: "access_token_value",
               id_token: "id_token_value",
               token_type: "bearer",
               expires_in: 3600,
               state: "state_value"
             }
    end

    test "excludes nil values from params" do
      response = %FormPostResponse{
        redirect_uri: "http://redirect.uri",
        code: "authorization_code",
        access_token: nil,
        id_token: nil,
        token_type: nil,
        expires_in: nil,
        state: nil,
        type: :code
      }

      assert FormPostResponse.params(response) == %{
               code: "authorization_code"
             }
    end
  end
end
