defmodule Boruta.Openid.UserinfoResponseTest do
  use ExUnit.Case, assync: true

  alias Boruta.Oauth.Client
  alias Boruta.Openid.UserinfoResponse

  describe "from_userinfo/2" do
    test "returns userinfo without client userinfo_signed_response_alg" do
      userinfo = %{"sub" => "sub"}
      client = %Client{id: SecureRandom.uuid()}

      assert %UserinfoResponse{
        userinfo: ^userinfo,
        format: :json
      } = UserinfoResponse.from_userinfo(userinfo, client)
    end

    test "returns userinfo with client userinfo_signed_response_alg" do
      userinfo = %{"sub" => "sub"}
      client = %Client{id: SecureRandom.uuid(), secret: "secret", userinfo_signed_response_alg: "HS256", signatures_adapter: "Elixir.Boruta.Internal.Signatures"}

      assert %UserinfoResponse{
        userinfo: ^userinfo,
        jwt: jwt,
        format: :jwt
      } = UserinfoResponse.from_userinfo(userinfo, client)

      # TODO test other client signing algorithms
      assert jwt
    end
  end

  describe "content_type/1" do
    test "returns mime type with json format" do
      response = %UserinfoResponse{userinfo: %{}, format: :json}

      assert UserinfoResponse.content_type(response) == "application/json"
    end

    test "returns mime type with jwt format" do
      response = %UserinfoResponse{userinfo: %{}, format: :jwt}

      assert UserinfoResponse.content_type(response) == "application/jwt"
    end
  end

  describe "payload/1" do
    test "returns payload with json format" do
      userinfo = %{"sub" => "sub"}
      response = %UserinfoResponse{userinfo: userinfo, format: :json}

      assert UserinfoResponse.payload(response) == userinfo
    end

    test "returns payload with jwt format" do
      jwt = "jwt"
      response = %UserinfoResponse{userinfo: %{}, jwt: jwt, format: :jwt}

      # TODO test jwt signature and payload
      assert UserinfoResponse.payload(response)
    end
  end
end
