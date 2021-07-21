defmodule Boruta.TokenGenerator do
  @moduledoc false

  defmodule Token do
    @moduledoc false

    use Joken.Config
  end

  @behaviour Boruta.Oauth.TokenGenerator

  import Boruta.Config,
    only: [
      resource_owners: 0,
      issuer: 0
    ]

  alias Boruta.Oauth

  use Puid, bits: 512, charset: :alphanum

  @impl Boruta.Oauth.TokenGenerator
  def generate(:id_token, %Oauth.Token{sub: sub, client: client}) do
    payload =
      resource_owners().claims(sub)
      |> Map.put("sub", sub)
      |> Map.put("iss", issuer())

    signer = Joken.Signer.create("RS512", %{"pem" => client.private_key})

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
end
