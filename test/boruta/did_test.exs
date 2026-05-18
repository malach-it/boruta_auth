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
  end
end
