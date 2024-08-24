defmodule Boruta.Did do
  @moduledoc """
    Utilities to manipulate dids using an universal resolver or registrar.
  """

  import Boruta.Config, only: [
    universal_did_auth: 0,
    universalresolver_base_url: 0,
    universalregistrar_base_url: 0
  ]

  @spec resolve(did :: String.t()) :: {:ok, did_document :: map()} | {:error, reason :: String.t()}
  def resolve(did) do
    resolver_url = "#{universalresolver_base_url()}/identifiers/#{did}"

    case Finch.build(:get, resolver_url) |> Finch.request(OpenIDHttpClient) do
      {:ok, %Finch.Response{body: body, status: 200}} ->
        Jason.decode(body)
      {:ok, %Finch.Response{body: body}} ->
          {:error, body}
      {:error, error} ->
          {:error, inspect(error)}
    end
  end

  @spec create(method :: String.t(), jwk :: map()) :: {:ok, did :: String.t()} | {:error, reason :: String.t()}
  def create(method, jwk) do
    payload = %{
      "didDocument" => %{
        "@context" => ["https//www.w3.org/ns/did/v1"],
        "service" => [],
        "verificationMethod" => [%{
          "id" => "#temp",
          "type" => "JsonWebKey2020",
          "publicKeyJwk" => jwk
        }]
      },
      "options" => %{
        "keyType" => "Ed25519",
        "clientSecretMode" => true,
        "JwkJcsPub" => true
      },
      "secret" => %{}
    }

    case Finch.build(
      :post,
      universalregistrar_base_url() <> "/create?method=#{method}",
      [
        {"Authorization", "Bearer #{universal_did_auth()[:token]}"},
        {"Content-Type", "application/json"}
      ],
      Jason.encode!(payload)
    ) |> Finch.request(OpenIDHttpClient) do
      {:ok, %Finch.Response{status: 201, body: body}} ->
        %{"didState" => %{"did" => did}} = Jason.decode!(body)
        {:ok, did}
      _ ->
        {:error, "Could not create did."}
    end
  end
end
