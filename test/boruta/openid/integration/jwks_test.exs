defmodule Boruta.OpenidTest.JwksTest do
  use Boruta.DataCase

  import Boruta.Factory

  alias Boruta.Openid
  alias Boruta.Openid.ApplicationMock

  describe "list clients jwk keys" do
    test "returns public client jwk" do
      assert {:jwk_list, jwks} = Openid.jwks(%Plug.Conn{}, ApplicationMock)
      assert Enum.count(jwks) == 1
    end

    test "list all clients jwk keys" do
      _client_1 = insert(:client, public_key: public_key_fixture())
      _client_2 = insert(:client, public_key: public_key_fixture())

      assert {:jwk_list, jwk_keys} = Openid.jwks(%Plug.Conn{}, ApplicationMock)

      assert Enum.member?(jwk_keys, %{
               "kid" => "Ac9ufCpgwReXGJ6LI",
               "e" => "AQAB",
               "kty" => "RSA",
               "n" =>
                 "1PaP_gbXix5itjRCaegvI_B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86-2DlL7pwUa9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3dGLJBB1r-Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey_U8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDw"
             })
    end
  end

  def public_key_fixture do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end
end
