defmodule Boruta.Did do
  # TODO integration tests
  @moduledoc """
    Utilities to manipulate dids.
  """

  import Boruta.Config,
    only: [
      universal_did_auth: 0,
      ebsi_did_resolver_base_url: 0,
      did_resolver_base_url: 0
    ]

  alias Boruta.Did.Crypto

  @spec resolve(did :: String.t()) ::
          {:ok, did_document :: map()} | {:error, reason :: String.t()}
  def resolve("did:key:" <> _key = did_url) do
    did = controller(did_url)
    "did:key:" <> fingerprint = did

    with {:ok, jwk} <- Crypto.public_key_jwk(fingerprint) do
      {:ok, key_did_document(did, fingerprint, jwk)}
    end
  end

  def resolve("did:ebsi" <> _key = did) do
    resolver_url = "#{ebsi_did_resolver_base_url()}/identifiers/#{did}"

    case Finch.build(:get, resolver_url)
         |> Finch.request(OpenIDHttpClient) do
      {:ok, %Finch.Response{body: body, status: 200}} ->
        case Jason.decode(body) do
          {:ok, %{"didDocument" => did_document}} ->
            {:ok, did_document}

          {:ok, did_document} ->
            {:ok, did_document}

          {:error, error} ->
            {:error, error}
        end

      {:ok, %Finch.Response{body: body}} ->
        {:error, body}

      {:error, error} ->
        {:error, inspect(error)}
    end
  end

  def resolve(did), do: resolve_universal(did)

  defp resolve_universal(did) do
    resolver_url = "#{did_resolver_base_url()}/identifiers/#{did}"

    with {:ok, %Finch.Response{body: body, status: 200}} <-
           Finch.build(:get, resolver_url, [
             {"Authorization", "Bearer #{universal_did_auth()[:token]}"}
           ])
           |> Finch.request(OpenIDHttpClient),
         {:ok, %{"didDocument" => did_document}} <- Jason.decode(body) do
      {:ok, did_document}
    else
      {:ok, %Finch.Response{body: body}} ->
        {:error, body}

      {:error, error} ->
        {:error, inspect(error)}

      {:ok, response} ->
        {:error, "Invalid resolver response: \"#{inspect(response)}\""}
    end
  end

  @spec create(method :: String.t()) ::
          {:ok, did :: String.t(), jwk :: map()} | {:error, reason :: String.t()}
  @spec create(method :: String.t(), jwk :: map() | nil) ::
          {:ok, did :: String.t(), jwk :: map()} | {:error, reason :: String.t()}
  def create(method, jwk \\ nil)

  def create("key", nil) do
    jwk =
      JOSE.JWK.generate_key({:okp, :Ed25519})
      |> JOSE.JWK.to_public()
      |> jwk_to_map()

    create("key", jwk)
  end

  def create("key", jwk) when is_map(jwk) do
    Crypto.did_key(jwk)
  end

  def create(_method, _jwk), do: {:error, "Could not create did."}

  @spec controller(did :: String.t() | nil) :: controller :: String.t() | nil
  def controller(nil), do: nil
  def controller(did), do: String.split(did, "#") |> List.first()

  defp jwk_to_map(jwk) do
    {_fields, jwk} = JOSE.JWK.to_map(jwk)
    jwk
  end

  defp key_did_document(did, fingerprint, jwk) do
    verification_method_id = did <> "#" <> fingerprint

    %{
      "@context" => [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/jws-2020/v1"
      ],
      "id" => did,
      "verificationMethod" => [
        %{
          "id" => verification_method_id,
          "type" => "JsonWebKey2020",
          "controller" => did,
          "publicKeyJwk" => jwk
        }
      ],
      "authentication" => [verification_method_id],
      "assertionMethod" => [verification_method_id],
      "capabilityInvocation" => [verification_method_id],
      "capabilityDelegation" => [verification_method_id]
    }
  end
end
