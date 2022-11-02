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

    test "registers a client" do
      redirect_uris = ["http://redirect.uri"]

      registration_params = %{
        redirect_uris: redirect_uris
      }

      assert {:client_registered, %Oauth.Client{redirect_uris: ^redirect_uris}} =
               Openid.register_client(:context, registration_params, ApplicationMock)
    end
  end
end
