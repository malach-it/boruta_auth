defmodule Boruta.OpenidTest.DynamicRegistrationTest do
  use Boruta.DataCase

  alias Boruta.Oauth
  alias Boruta.Openid
  alias Boruta.Openid.ApplicationMock

  describe "client registration" do
    test "returns an error" do
      redirect_uris = nil

      registration_params = %{
        redirect_uris: redirect_uris
      }

      assert {:registration_failure, %Ecto.Changeset{}} =
               Openid.register_client(:context, registration_params, ApplicationMock)
    end

    test "returns an error with a fragment in redirect uri" do
      redirect_uris = ["http://redirect.uri#test"]

      registration_params = %{
        redirect_uris: redirect_uris
      }

      assert {:registration_failure, %Ecto.Changeset{}} =
               Openid.register_client(:context, registration_params, ApplicationMock)
    end

    test "registers a client" do
      jwk = %{
        "kty" => "RSA",
        "e" => "AQAB",
        "use" => "sig",
        "alg" => "RS256",
        "n" =>
          "iN2CZVIKWB--I5yxqQtwLWncQR_N7u7Ge0bE3zqj4tqKVSHgBEE3xobV-nOKisAJzCy1QhJb7Cy9MQYxBZ09HbAXvZVHVFRtrTcFk87ZcB_7H8T_Nh_uydJEjiW--ryP1klNefa9V4t3WCwmNgX1ipP0ZHhNenemOT9BASQyF-_5Gm7KsDxJ8DkZH_OQhl5xdqXwZOh5Y7Cc25ZB1sr9xRse4vah9uiS5YgwTFbGRzS-yIDKuSB8BY1cBT0uwBLICamgI7gV0oZkQ29_ptXPZC1tw3X41eNaPU-G2ocF2vKZwBdGO8weTMfQngjPZ_xKv_y9_Y7P5aF-L3F05eKVjQ"
      }

      redirect_uris = ["http://redirect.uri"]

      registration_params = %{
        redirect_uris: redirect_uris,
        jwk: jwk
      }

      assert {:client_registered,
              %Oauth.Client{redirect_uris: ^redirect_uris, jwt_public_key: jwt_public_key}} =
               Openid.register_client(:context, registration_params, ApplicationMock)

      assert JOSE.JWK.from_pem(jwt_public_key).kty == JOSE.JWK.from_map(jwk).kty
    end
  end
end
