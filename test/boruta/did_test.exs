defmodule Boruta.DidTest do
  use ExUnit.Case, async: true

  alias Boruta.Did

  describe "controller/1" do
    test "removes verification method fragments and preserves nil" do
      assert Did.controller("did:example:123#key-1") == "did:example:123"
      assert Did.controller("did:example:123") == "did:example:123"
      assert Did.controller(nil) == nil
    end
  end

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
  end
end
