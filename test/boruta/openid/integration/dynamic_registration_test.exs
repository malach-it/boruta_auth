defmodule Boruta.OpenidTest.DynamicRegistrationTest do
  use Boruta.DataCase

  alias Boruta.Oauth
  alias Boruta.Openid
  alias Boruta.Openid.ApplicationMock

  describe "client registration" do
    setup do
      bypass = Bypass.open()

      {:ok, bypass: bypass}
    end

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

    test "registers a client with name" do
      name = "client name"

      registration_params = %{
        client_name: name
      }

      assert {:client_registered, %Oauth.Client{name: ^name}} =
               Openid.register_client(:context, registration_params, ApplicationMock)
    end

    test "registers a client with token_endpoint_auth_method" do
      auth_method = "private_key_jwt"

      registration_params = %{
        token_endpoint_auth_method: auth_method
      }

      assert {:client_registered, %Oauth.Client{token_endpoint_auth_methods: [^auth_method]}} =
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

    test "registers a client with a jwks" do
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
        jwks: %{keys: [jwk]}
      }

      assert {:client_registered,
              %Oauth.Client{
                redirect_uris: ^redirect_uris,
                jwt_public_key: jwt_public_key,
                token_endpoint_jwt_auth_alg: "RS256"
              }} = Openid.register_client(:context, registration_params, ApplicationMock)

      assert JOSE.JWK.from_pem(jwt_public_key).kty == JOSE.JWK.from_map(jwk).kty
    end

    test "registers a client with a jwks_uri", %{bypass: bypass} do
      jwk = %{
        "kty" => "RSA",
        "e" => "AQAB",
        "use" => "sig",
        "alg" => "RS256",
        "n" =>
          "iN2CZVIKWB--I5yxqQtwLWncQR_N7u7Ge0bE3zqj4tqKVSHgBEE3xobV-nOKisAJzCy1QhJb7Cy9MQYxBZ09HbAXvZVHVFRtrTcFk87ZcB_7H8T_Nh_uydJEjiW--ryP1klNefa9V4t3WCwmNgX1ipP0ZHhNenemOT9BASQyF-_5Gm7KsDxJ8DkZH_OQhl5xdqXwZOh5Y7Cc25ZB1sr9xRse4vah9uiS5YgwTFbGRzS-yIDKuSB8BY1cBT0uwBLICamgI7gV0oZkQ29_ptXPZC1tw3X41eNaPU-G2ocF2vKZwBdGO8weTMfQngjPZ_xKv_y9_Y7P5aF-L3F05eKVjQ"
      }

      redirect_uris = ["http://redirect.uri"]

      jwks_uri = "http://localhost:#{bypass.port}/jwks"

      Bypass.expect_once(bypass, "GET", "/jwks", fn conn ->
        Plug.Conn.resp(conn, 200, Jason.encode!(%{"keys" => [jwk]}))
      end)

      registration_params = %{
        redirect_uris: redirect_uris,
        jwks_uri: jwks_uri
      }

      assert {:client_registered,
              %Oauth.Client{
                redirect_uris: ^redirect_uris,
                jwt_public_key: jwt_public_key,
                token_endpoint_jwt_auth_alg: "RS256"
              }} = Openid.register_client(:context, registration_params, ApplicationMock)

      assert JOSE.JWK.from_pem(jwt_public_key).kty == JOSE.JWK.from_map(jwk).kty
    end
  end
end
