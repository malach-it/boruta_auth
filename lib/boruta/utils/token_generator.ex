defmodule Boruta.TokenGenerator do
  @moduledoc false

  defmodule Token do
    @moduledoc false

    use Joken.Config

    def token_config, do: %{}
  end

  @behaviour Boruta.Oauth.TokenGenerator

  use Puid, bits: 512, charset: :alphanum

  import Boruta.Config,
    only: [
      resource_owners: 0,
      issuer: 0
    ]

  alias Boruta.Oauth

  @id_token_alg "RS512"
  @id_token_c_hash_alg :sha512

  @impl Boruta.Oauth.TokenGenerator
  def generate(:id_token, %Oauth.Token{type: "code"} = token) do
    payload =
      id_token_payload(token)
      |> Map.put("c_hash", c_hash(token.value))

    signer = Joken.Signer.create(@id_token_alg, %{"pem" => token.client.private_key})

    with {:ok, token, _payload} <- Token.encode_and_sign(payload, signer) do
      token
    end
  end

  def generate(:id_token, token) do
    payload = id_token_payload(token)

    signer = Joken.Signer.create(@id_token_alg, %{"pem" => token.client.private_key})

    with {:ok, token, _payload} <- Token.encode_and_sign(payload, signer) do
      token
    end
  end

  def generate(_, _) do
    generate()
  end

  @impl Boruta.Oauth.TokenGenerator
  def secret(_) do
    generate()
  end

  defp c_hash(code) do
    :crypto.hash(@id_token_c_hash_alg, code)
    |> binary_part(0, 32)
    |> Base.url_encode64()
    |> String.replace("=", "")
  end

  defp id_token_payload(%Oauth.Token{
         sub: sub,
         client: client,
         inserted_at: inserted_at,
         nonce: nonce,
         scope: scope
       }) do
    iat = DateTime.to_unix(inserted_at)

    resource_owners().claims(sub, scope)
    |> Map.put("sub", sub)
    |> Map.put("iss", issuer())
    |> Map.put("aud", client.id)
    |> Map.put("iat", iat)
    |> Map.put("exp", iat + client.id_token_ttl)
    |> Map.put("nonce", nonce)
  end
end
