defmodule Boruta.Universal.Signatures do
  @behaviour Boruta.Oauth.Signatures

  defmodule Token do
    @moduledoc false

    use Joken.Config

    def token_config, do: %{}
  end

  @moduledoc false

  import Boruta.Config, only: [
    universal_did_auth: 0,
    signature_credentials_base_url: 0
  ]

  alias Boruta.Internal.Signatures.SigningKey
  alias Boruta.Oauth.Client

  @signature_algorithms [
    ES256: [type: :asymmetric, hash_algorithm: :SHA256, binary_size: 16],
    ES384: [type: :asymmetric, hash_algorithm: :SHA384, binary_size: 24],
    ES512: [type: :asymmetric, hash_algorithm: :SHA512, binary_size: 32],
    RS256: [type: :asymmetric, hash_algorithm: :SHA256, binary_size: 16],
    RS384: [type: :asymmetric, hash_algorithm: :SHA384, binary_size: 24],
    RS512: [type: :asymmetric, hash_algorithm: :SHA512, binary_size: 32],
    HS256: [type: :symmetric, hash_algorithm: :SHA256, binary_size: 16],
    HS384: [type: :symmetric, hash_algorithm: :SHA384, binary_size: 24],
    HS512: [type: :symmetric, hash_algorithm: :SHA512, binary_size: 32]
  ]

  @spec signature_algorithms() :: list(atom())
  def signature_algorithms, do: Keyword.keys(@signature_algorithms)

  @spec hash_alg(Client.t()) :: hash_alg :: atom()
  def hash_alg(%Client{id_token_signature_alg: signature_alg}),
    do: @signature_algorithms[String.to_atom(signature_alg)][:hash_algorithm]

  @spec hash_binary_size(Client.t()) :: binary_size :: integer()
  def hash_binary_size(%Client{id_token_signature_alg: signature_alg}),
    do: @signature_algorithms[String.to_atom(signature_alg)][:binary_size]

  @spec hash(string :: String.t(), client :: Client.t()) :: hash :: String.t()
  def hash(string, client) do
    hash_alg(client)
    |> Atom.to_string()
    |> String.downcase()
    |> String.to_atom()
    |> :crypto.hash(string)
    |> binary_part(0, hash_binary_size(client))
    |> Base.url_encode64(padding: false)
  end

  @spec id_token_sign(payload :: map(), client :: Client.t()) ::
          jwt :: String.t() | {:error, reason :: String.t()}
  def id_token_sign(
        payload,
        %Client{
          id_token_signature_alg: signature_alg
        } = client
      ) do
    with {:ok, signing_key} <- get_signing_key(client, :id_token) do
      signer =
        case id_token_signature_type(client) do
          :symmetric ->
            Joken.Signer.create(signature_alg, signing_key.secret)

          :asymmetric ->
            Joken.Signer.create(
              signature_alg,
              %{"pem" => signing_key.private_key},
              %{
                "kid" => signing_key.kid,
                "trust_chain" => signing_key.trust_chain
              }
            )
        end

      case Token.encode_and_sign(payload, signer) do
        {:ok, token, _payload} ->
          token

        {:error, error} ->
          {:error, "Could not sign the given payload with client credentials: #{inspect(error)}"}
      end
    end
  end

  @spec verify_id_token_signature(id_token :: String.t(), jwk :: JOSE.JWK.t()) ::
          :ok | {:error, reason :: String.t()}
  def verify_id_token_signature(id_token, jwk) do
    case Joken.peek_header(id_token) do
      {:ok, %{"alg" => alg}} ->
        signer = Joken.Signer.create(alg, %{"pem" => JOSE.JWK.from_map(jwk) |> JOSE.JWK.to_pem()})

        case Token.verify(id_token, signer) do
          {:ok, claims} -> {:ok, claims}
          {:error, reason} -> {:error, inspect(reason)}
        end

      {:error, reason} ->
        {:error, inspect(reason)}
    end
  end

  @spec userinfo_sign(payload :: map(), client :: Client.t()) ::
          jwt :: String.t() | {:error, reason :: String.t()}
  def userinfo_sign(
        payload,
        %Client{
          userinfo_signed_response_alg: signature_alg
        } = client
      ) do
    with {:ok, signing_key} <- get_signing_key(client, :userinfo) do
      signer =
        case userinfo_signature_type(client) do
          :symmetric ->
            Joken.Signer.create(signature_alg, signing_key.secret)

          :asymmetric ->
            Joken.Signer.create(
              signature_alg,
              %{"pem" => signing_key.private_key},
              %{
                "kid" => signing_key.kid,
                "trust_chain" => signing_key.trust_chain
              }
            )
        end

      case Token.encode_and_sign(payload, signer) do
        {:ok, token, _payload} ->
          token

        {:error, error} ->
          {:error, "Could not sign the given payload with client credentials: #{inspect(error)}"}
      end
    end
  end

  @universal_format %{
    "jwt_vc" => "jwt"
  }
  @spec verifiable_credential_sign(payload :: map(), client :: Client.t(), format :: String.t()) ::
          jwt :: String.t() | {:error, reason :: String.t()}
  def verifiable_credential_sign(
        credential,
        %Client{
          id_token_signature_alg: signature_alg
        } = client,
        format
      ) do
    payload = %{
      "credential" => credential,
      "options" => %{
        "format" => @universal_format[format]
      }
    }
    case Finch.build(:post, signature_credentials_base_url(), [
           {"Authorization", "Bearer #{universal_did_auth()[:token]}"},
           {"Content-Type", "application/json"}
         ], Jason.encode!(payload))
         |> Finch.request(OpenIDHttpClient) |> dbg do
      {:ok, %Finch.Response{body: body, status: 201}} ->
        body
      {:ok, %Finch.Response{body: body}} ->
        {:error, "Could not sign verifiable credential - #{body}"}
      {:error, error} ->
        {:error, "Could not sign verifiable credential - #{inspect(error)}"}
    end
  end

  @spec kid_from_private_key(private_pem :: String.t()) :: kid :: String.t()
  def kid_from_private_key(private_pem) do
    :crypto.hash(:md5, private_pem) |> Base.url_encode64() |> String.slice(0..16)
  end

  @spec userinfo_signature_type(Client.t()) :: userinfo_token_signature_type :: atom()
  def userinfo_signature_type(%Client{userinfo_signed_response_alg: signature_alg}),
    do: @signature_algorithms[String.to_atom(signature_alg)][:type]

  @spec id_token_signature_type(Client.t()) :: id_token_signature_type :: atom()
  def id_token_signature_type(%Client{id_token_signature_alg: signature_alg}),
    do: @signature_algorithms[String.to_atom(signature_alg)][:type]

  defp get_signing_key(client, :id_token) do
    {:ok,
     %SigningKey{
       type: :internal,
       private_key: client.private_key,
       secret: client.secret,
       kid: client.id_token_kid || kid_from_private_key(client.private_key)
     }}
  end

  defp get_signing_key(client, :userinfo) do
    {:ok,
     %SigningKey{
       type: :internal,
       private_key: client.private_key,
       secret: client.secret,
       kid: client.id
     }}
  end

  defp get_signing_key(client, :verifiable_credential) do
    {:ok,
     %SigningKey{
       type: :internal,
       private_key: client.private_key,
       secret: client.secret,
       kid: client.did || client.id_token_kid || kid_from_private_key(client.private_key)
     }}
  end
end
