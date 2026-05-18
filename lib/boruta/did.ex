defmodule Boruta.Did do
  # TODO integration tests
  @moduledoc """
    Utilities to manipulate dids using an universal resolver or registrar.
  """

  import Boruta.Config,
    only: [
      universal_did_auth: 0,
      ebsi_did_resolver_base_url: 0,
      did_resolver_base_url: 0,
      did_registrar_base_url: 0
    ]

  alias Boruta.Did.Crypto

  @spec resolve(did :: String.t()) ::
          {:ok, did_document :: map()} | {:error, reason :: String.t()}
  def resolve("did:key:" <> fingerprint = did) do
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

  def resolve(did) do
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

  @dialyzer {:no_return, create: 1}
  @dialyzer {:no_return, create: 2}
  @spec create(method :: String.t()) ::
          {:ok, did :: String.t(), jwk :: map()} | {:error, reason :: String.t()}
  @spec create(method :: String.t(), jwk :: map() | nil) ::
          {:ok, did :: String.t(), jwk :: map()} | {:error, reason :: String.t()}
  def create(method, jwk \\ nil)

  def create("key", jwk) when is_map(jwk) do
    Crypto.did_key(jwk)
  end

  def create("key" = method, nil) do
    payload = %{
      "didDocument" => %{
        "@context" => ["https//www.w3.org/ns/did/v1"],
        "service" => []
      },
      "secret" => %{}
    }

    payload =
      Map.put(payload, "options", %{
        "keyType" => "Ed25519",
        "jwkJcsPub" => true
      })

    with {:ok, %Finch.Response{status: 201, body: body}} <-
           Finch.build(
             :post,
             did_registrar_base_url() <> "/create?method=#{method}",
             [
               {"Authorization", "Bearer #{universal_did_auth()[:token]}"},
               {"Content-Type", "application/json"}
             ],
             Jason.encode!(payload)
           )
           |> Finch.request(OpenIDHttpClient),
         %{
           "didState" => %{
             "did" => did
           }
         } <- Jason.decode!(body),
         {:ok, %{"verificationMethod" => [%{"publicKeyJwk" => jwk}]}} <- resolve(did) do
      {:ok, did, jwk}
    else
      _ ->
        {:error, "Could not create did."}
    end
  end

  @spec controller(did :: String.t() | nil) :: controller :: String.t() | nil
  def controller(nil), do: nil
  def controller(did), do: String.split(did, "#") |> List.first()

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
