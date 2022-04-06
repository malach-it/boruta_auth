defmodule Boruta.OpenidTest.JwksTest do
  use Boruta.DataCase

  import Boruta.Factory

  alias Boruta.Openid
  alias Boruta.Openid.ApplicationMock

  describe "list clients jwk keys" do
    test "returns an empty array" do
      assert Openid.jwks(%Plug.Conn{}, ApplicationMock) == {:jwk_list, []}
    end

    test "list all clients jwk keys" do
      client_1 = insert(:client, public_key: public_key_fixture())
      client_2 = insert(:client, public_key: public_key_fixture())

      assert {:jwk_list, jwk_keys} = Openid.jwks(%Plug.Conn{}, ApplicationMock)

      assert Enum.sort(jwk_keys) == [
        %{:kid => client_1.id, "e" => "AQAB", "kty" => "RSA", "n" => "1PaP_gbXix5itjRCaegvI_B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86-2DlL7pwUa9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3dGLJBB1r-Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey_U8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDw"},
        %{:kid => client_2.id, "e" => "AQAB", "kty" => "RSA", "n" => "1PaP_gbXix5itjRCaegvI_B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86-2DlL7pwUa9QyHsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3dGLJBB1r-Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey_U8xDZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0AEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDw"}
      ] |> Enum.sort()
    end
  end

  def public_key_fixture do
    "-----BEGIN RSA PUBLIC KEY-----\nMIIBCgKCAQEA1PaP/gbXix5itjRCaegvI/B3aFOeoxlwPPLvfLHGA4QfDmVOf8cU\n8OuZFAYzLArW3PnnwWWy39nVJOx42QRVGCGdUCmV7shDHRsr86+2DlL7pwUa9QyH\nsTj84fAJn2Fv9h9mqrIvUzAtEYRlGFvjVTGCwzEullpsB0GJafopUTFby8WdSq3d\nGLJBB1r+Q8QtZnAxxvolhwOmYkBkkidefmm48X7hFXL2cSJm2G7wQyinOey/U8xD\nZ68mgTakiqS2RtjnFD0dnpBl5CYTe4s6oZKEyFiFNiW4KkR1GVjsKwY9oC2tpyQ0\nAEUMvk9T9VdIltSIiAvOKlwFzL49cgwZDwIDAQAB\n-----END RSA PUBLIC KEY-----\n\n"
  end
end
