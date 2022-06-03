defmodule Boruta.Oauth.IdToken do
  @moduledoc """
  OpenID Connect id token schema and utilities
  """

  defmodule Token do
    @moduledoc false

    use Joken.Config

    def token_config, do: %{}
  end

  import Boruta.Config, only: [resource_owners: 0, issuer: 0]

  alias Boruta.Oauth

  @hashing_algorithms [
    RS256: :SHA256,
    RS384: :SHA384,
    RS512: :SHA512
  ]

  @spec signature_algorithms() :: list(atom())
  def signature_algorithms, do: Keyword.keys(@hashing_algorithms)

  @spec hash_alg(Oauth.Client.t()) :: hash_alg :: atom()
  def hash_alg(%Oauth.Client{id_token_signature_alg: signature_alg}),
    do: @hashing_algorithms[String.to_atom(signature_alg)]

  @type tokens :: %{
          optional(:code) => %Oauth.Token{
            sub: String.t(),
            client: Oauth.Client.t(),
            inserted_at: DateTime.t(),
            scope: String.t()
          },
          optional(:token) => %Oauth.Token{
            sub: String.t(),
            client: Oauth.Client.t(),
            inserted_at: DateTime.t(),
            scope: String.t()
          },
          optional(:base_token) => %Oauth.Token{
            sub: String.t(),
            client: Oauth.Client.t(),
            inserted_at: DateTime.t(),
            scope: String.t()
          }
        }

  @spec generate(tokens :: tokens(), nonce :: String.t()) :: id_token :: Oauth.Token.t()
  def generate(tokens, nonce) do
    {base_token, payload} = payload(tokens, nonce, %{})

    value = sign(payload, base_token.client)
    %{base_token | type: "id_token", value: value}
  end

  defp payload(%{code: code} = tokens, nonce, acc) do
    tokens
    |> Map.put(:base_token, code)
    |> Map.delete(:code)
    |> payload(nonce, Map.put(acc, "c_hash", hash(code.value, code.client)))
  end

  defp payload(%{token: token} = tokens, nonce, acc) do
    tokens
    |> Map.put(:base_token, token)
    |> Map.delete(:token)
    |> payload(nonce, Map.put(acc, "at_hash", hash(token.value, token.client)))
  end

  defp payload(%{base_token: base_token}, nonce, acc) do
    {base_token, Map.merge(acc, payload(base_token, nonce))}
  end

  defp payload(
         %Oauth.Token{
           sub: sub,
           client: client,
           inserted_at: inserted_at,
           scope: scope,
           resource_owner: resource_owner
         },
         nonce
       ) do
    iat = DateTime.to_unix(inserted_at)

    auth_time =
      case resource_owner.last_login_at do
        nil -> :os.system_time(:seconds)
        last_login_at -> DateTime.to_unix(last_login_at)
      end

    resource_owners().claims(resource_owner, scope)
    |> Map.put("sub", sub)
    |> Map.put("iss", issuer())
    |> Map.put("aud", client.id)
    |> Map.put("iat", iat)
    |> Map.put("auth_time", auth_time)
    |> Map.put("exp", iat + client.id_token_ttl)
    |> Map.put("nonce", nonce)
  end

  defp sign(payload, %Oauth.Client{
         id_token_signature_alg: signature_alg,
         private_key: private_key
       }) do
    signer = Joken.Signer.create(signature_alg, %{"pem" => private_key})

    with {:ok, token, _payload} <- Token.encode_and_sign(payload, signer) do
      token
    end
  end

  defp hash(string, client) do
    hash_alg(client)
    |> Atom.to_string()
    |> String.downcase()
    |> String.to_atom()
    |> :crypto.hash(string)
    |> binary_part(0, 32)
    |> Base.url_encode64(padding: false)
  end
end
