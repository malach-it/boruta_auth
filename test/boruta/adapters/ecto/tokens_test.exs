defmodule Boruta.Ecto.TokensTest do
  use Boruta.DataCase

  alias Boruta.Ecto.AccessTokens
  alias Boruta.Ecto.Codes
  alias Boruta.Ecto.TokenStore
  alias Boruta.Oauth

  test "returns not found errors when revoking a missing access token" do
    token = %Oauth.Token{
      type: "access_token",
      client: client(),
      value: "missing-access-token"
    }

    assert {:error, "Token not found."} = AccessTokens.revoke(token)
    assert {:error, "Token not found."} = AccessTokens.revoke_refresh_token(token)
  end

  test "rejects a cached code when its redirect URI does not match" do
    code = %Oauth.Token{
      type: "code",
      client: client(),
      value: "cached-code-#{System.unique_integer([:positive])}",
      redirect_uri: "https://client.example.com/callback"
    }

    assert {:ok, ^code} = TokenStore.put(code)

    on_exit(fn ->
      TokenStore.invalidate(code)
    end)

    assert Codes.get_by(
             value: code.value,
             redirect_uri: "https://attacker.example.com/callback"
           ) == nil
  end

  test "returns an error when revoking a missing authorization code" do
    code = %Oauth.Token{
      type: "code",
      client: client(),
      value: "missing-code"
    }

    assert {:error, "Code not found."} = Codes.revoke(code)
  end

  defp client do
    %Oauth.Client{
      id: SecureRandom.uuid(),
      access_token_ttl: 60,
      authorization_code_ttl: 60
    }
  end
end
