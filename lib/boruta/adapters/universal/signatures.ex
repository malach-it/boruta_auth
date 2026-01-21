defmodule Boruta.Universal.Signatures do
  @behaviour Boruta.Oauth.Signatures

  import Boruta.Config, only: [resource_owners: 0]

  defmodule Token do
    @moduledoc false

    use Joken.Config

    def token_config, do: %{}
  end

  @moduledoc false

  alias Boruta.Oauth.Client
  alias Boruta.Universal.Signatures.SigningKey

  @signature_algorithms [
    EdDSA: [type: :asymmetric, hash_algorithm: :SHA256, binary_size: 16],
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
        %Client{} = client
      ) do
    with {:ok, key} <- get_signing_key(client, :id_token),
         {:ok, token} <- SigningKey.encode_and_sign_with_key(key, payload) do
        token

      else
      {:error, error} ->
        {:error, "Could not sign the given payload with client credentials: #{inspect(error)}"}
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

  @spec verifiable_credential_sign(payload :: map(), client :: Client.t(), format :: String.t()) ::
          jwt :: String.t() | {:error, reason :: String.t()}
  def verifiable_credential_sign(
        credential,
        %Client{} = client,
        _format
      ) do
        with {:ok, key} <- get_signing_key(client, :verifiable_credential),
             {:ok, credential} <- SigningKey.encode_and_sign_with_key(key, credential) do
        credential
    end
  end

  @spec userinfo_signature_type(Client.t()) :: userinfo_token_signature_type :: atom()
  def userinfo_signature_type(%Client{userinfo_signed_response_alg: signature_alg}),
    do: @signature_algorithms[String.to_atom(signature_alg)][:type]

  @spec id_token_signature_type(Client.t()) :: id_token_signature_type :: atom()
  def id_token_signature_type(%Client{id_token_signature_alg: signature_alg}),
    do: @signature_algorithms[String.to_atom(signature_alg)][:type]

  defp get_signing_key(client, :id_token) do
    with {:ok, trust_chain} <- resource_owners().trust_chain(client) do
      {:ok,
       %SigningKey{
         type: :internal,
         private_key: client.private_key,
         public_key: client.public_key,
         secret: client.secret,
         kid: client.did,
         trust_chain: trust_chain
       }}
    end
  end

  defp get_signing_key(client, :userinfo) do
    {:ok,
     %SigningKey{
       type: :internal,
       private_key: client.private_key,
       public_key: client.public_key,
       secret: client.secret,
       kid: client.did
     }}
  end

  defp get_signing_key(client, :verifiable_credential) do
    with {:ok, trust_chain} <- resource_owners().trust_chain(client) do
      {:ok,
       %SigningKey{
         type: :universal,
         private_key: client.private_key,
         public_key: client.public_key,
         kid: client.did,
         trust_chain: trust_chain
       }}
    end
  end
end
