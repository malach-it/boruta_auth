defmodule Boruta.DidTest do
  use ExUnit.Case, async: true

  alias Boruta.Did

  describe "resolve/1" do
    test "resolves did:key Ed25519 documents locally" do
      did = "did:key:z6MkiTBzpb9TgRh9pMBC3y4f9Ldia1nq5QWa3tFdbwfBjPCi"

      assert {:ok,
              %{
                "id" => ^did,
                "verificationMethod" => [
                  %{
                    "id" => verification_method_id,
                    "controller" => ^did,
                    "type" => "JsonWebKey2020",
                    "publicKeyJwk" => %{
                      "kty" => "OKP",
                      "crv" => "Ed25519",
                      "x" => public_key
                    }
                  }
                ],
                "authentication" => [authentication_method_id],
                "assertionMethod" => [assertion_method_id]
              }} = Did.resolve(did)

      assert verification_method_id == did <> "#z6MkiTBzpb9TgRh9pMBC3y4f9Ldia1nq5QWa3tFdbwfBjPCi"
      assert authentication_method_id == verification_method_id
      assert assertion_method_id == verification_method_id
      assert is_binary(public_key)
    end

    test "resolves did:key RSA documents locally" do
      did =
        "did:key:z4MXj1wBzi9jUstyQAVUF6ibbHUd3jozWgVWFNHUEd8WFtuQAcRojJDf97jQeR6nA5PXoYC3nb1BrjbYQrxRWinvz5tjtMxT4fFTtHkxjojdoSyEdRBgEupBfhz5axKi9WE5hLS4eiwGLuaQWUq48manvZjSHUi3azj8exMDx2XKjHSeB2BuNr9Bwse3ts9MctQrNtDg2LP1R7ZRdUWQuqLzZ87bQJgJZ7BWqA92dfMcgZ17ZysNZmSfUgXxFXhyb42N8wnG8wxdWprmJv9wBsEXjcCUiJhdTu8NGABQQ2QNhNYVuwfHgCCsZqxkmVXMN9kynQV2NCNkPkLxNP3VzSMw7FLjLFMsnyPXd4ph9yyYF3iDmVKtC"

      assert {:ok,
              %{
                "id" => ^did,
                "verificationMethod" => [
                  %{
                    "publicKeyJwk" => %{
                      "kty" => "RSA",
                      "n" => modulus,
                      "e" => "AQAB"
                    }
                  }
                ]
              }} = Did.resolve(did)

      assert is_binary(modulus)
    end

    test "does not fall back to the universal resolver for malformed did:key values" do
      assert {:error, "Invalid did:key base58 fingerprint."} = Did.resolve("did:key:zinvalid0")
    end

    test "resolves did:key URLs with verification method fragments" do
      did =
        "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbtAoJqfb74EbV7paYy1ivneNPMf2t7GF6TaJHnbjBksaYALwBD8rhNUfY33KKCGALBKCjaaQpVRx36VZkqNQqYw5qsySyA631GsS2tKnPJ4fHPjmTjCygqMMNHtW1rEakiG"

      assert {:ok,
              %{
                "id" => ^did,
                "verificationMethod" => [
                  %{
                    "id" => verification_method_id,
                    "publicKeyJwk" => %{"kty" => "EC", "crv" => "P-256"}
                  }
                ]
              }} = Did.resolve(did <> "#" <> String.replace(did, "did:key:", ""))

      assert verification_method_id == did <> "#" <> String.replace(did, "did:key:", "")
    end

    test "resolves a local did:key JwkJcsPub DID document" do
      jwk = %{
        "crv" => "Ed25519",
        "kty" => "OKP",
        "x" => "sqA34wZlskczXTD6OwTIj4aFTd5ICalNa7a51hnPx1o"
      }

      assert {:ok, did, ^jwk} = Did.create("key", jwk)
      "did:key:" <> key = did

      assert {:ok,
              %{
                "id" => ^did,
                "verificationMethod" => [
                  %{
                    "id" => verification_method_id,
                    "type" => "JsonWebKey2020",
                    "controller" => ^did,
                    "publicKeyJwk" => ^jwk
                  }
                ],
                "authentication" => [verification_method_id],
                "assertionMethod" => [verification_method_id],
                "capabilityInvocation" => [verification_method_id],
                "capabilityDelegation" => [verification_method_id]
              }} = Did.resolve("#{did}##{key}")
    end

    test "resolves the existing z2dmz P-256 JwkJcsPub DID shape" do
      did =
        "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrSfZqXLVnTT5rRw7VCjbapSKSfZEUSekzuBrGZhfwxQTfsNVeUYsX5gH2eJ4LdVt6uctFyJsW76VygayYHiHpwnhGwAombiRJiimmRTMXUAa49VQ9NWT7PUK2P7VbBy4Bn"

      assert {:ok, %{"verificationMethod" => [%{"publicKeyJwk" => jwk}]}} = Did.resolve(did)

      assert jwk == %{
               "crv" => "P-256",
               "kty" => "EC",
               "x" => "dDrhCxO_15gxC4JKJyBbANQR_wL6-s2jTlmSvkqrDus",
               "y" => "IdFmumwAY51zD9Y6jo1UsVvulADadb81s58gm7hy1QU"
             }
    end

    test "rejects invalid local did:key values" do
      assert {:error, _error} = Did.resolve("did:key:invalid")
    end
  end

  describe "create/2" do
    test "creates did:key locally from a public RSA JWK" do
      {_type, jwk} =
        JOSE.JWK.generate_key({:rsa, 2048, 65_537})
        |> JOSE.JWK.to_public()
        |> JOSE.JWK.to_map()

      assert {:ok, "did:key:" <> _ = did, public_jwk} = Did.create("key", jwk)

      assert {:ok, %{"verificationMethod" => [%{"publicKeyJwk" => ^public_jwk}]}} =
               Did.resolve(did)
    end

    test "creates did:key locally from a public P-256 JWK" do
      {_type, jwk} =
        JOSE.JWK.generate_key({:ec, "P-256"})
        |> JOSE.JWK.to_public()
        |> JOSE.JWK.to_map()

      assert {:ok, "did:key:" <> _ = did, public_jwk} = Did.create("key", jwk)

      assert {:ok, %{"verificationMethod" => [%{"publicKeyJwk" => ^public_jwk}]}} =
               Did.resolve(did)
    end

    test "creates a local did:key from an Ed25519 public JWK" do
      jwk = %{
        "crv" => "Ed25519",
        "kty" => "OKP",
        "x" => "sqA34wZlskczXTD6OwTIj4aFTd5ICalNa7a51hnPx1o"
      }

      assert {:ok, "did:key:z" <> key, ^jwk} = Did.create("key", jwk)
      assert byte_size(key) > 0
    end

    test "creates a local did:key with a z2dmz prefix from a P-256 public JWK" do
      jwk = %{
        "crv" => "P-256",
        "kty" => "EC",
        "x" => "dDrhCxO_15gxC4JKJyBbANQR_wL6-s2jTlmSvkqrDus",
        "y" => "IdFmumwAY51zD9Y6jo1UsVvulADadb81s58gm7hy1QU"
      }

      assert {:ok, "did:key:z2dmz" <> _key, ^jwk} = Did.create("key", jwk)
    end

    test "creates a local did:key and public JWK when no JWK is given" do
      assert {:ok, "did:key:z" <> key, jwk} = Did.create("key")

      assert byte_size(key) > 0
      assert %{"crv" => "Ed25519", "kty" => "OKP", "x" => x} = jwk
      assert is_binary(x)
      refute Map.has_key?(jwk, "d")
    end

    test "only exposes the public part of a private JWK" do
      jwk = %{
        "crv" => "Ed25519",
        "d" => "PMiV0jR23UbFa-sSafE4iMsI4RFGQ_OmLBCZLB9JqE0",
        "kty" => "OKP",
        "x" => "sqA34wZlskczXTD6OwTIj4aFTd5ICalNa7a51hnPx1o"
      }

      assert {:ok, _did, public_jwk} = Did.create("key", jwk)
      refute Map.has_key?(public_jwk, "d")
    end
  end
end
