defmodule Boruta.Did.CryptoTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias Boruta.Did.Crypto

  @jwk_jcs_public_key_code 0xEB51

  describe "did_key/1" do
    test "creates deterministic, round-trippable DIDs for supported public JWKs" do
      jwks = [
        %{
          "kty" => "OKP",
          "crv" => "Ed25519",
          "x" => Base.url_encode64(:binary.copy(<<1>>, 32), padding: false)
        },
        ec_jwk("P-256", p256_x(), p256_y()),
        ec_jwk("secp256k1", secp256k1_x(), secp256k1_y()),
        rsa_jwk()
      ]

      Enum.each(jwks, fn jwk ->
        assert {:ok, "did:key:" <> fingerprint, public_jwk} = Crypto.did_key(jwk)
        assert {:ok, ^public_jwk} = Crypto.public_key_jwk(fingerprint)
        refute Map.has_key?(public_jwk, "d")
      end)
    end

    test "rejects unsupported and malformed public JWKs" do
      invalid_ed25519 = %{
        "kty" => "OKP",
        "crv" => "Ed25519",
        "x" => Base.url_encode64(<<1>>, padding: false)
      }

      invalid_ec = %{
        "kty" => "EC",
        "crv" => "P-256",
        "x" => "not-base64url",
        "y" => "not-base64url"
      }

      assert {:error, "Invalid did:key Ed25519 public key."} =
               Crypto.did_key(invalid_ed25519)

      assert {:error, "Invalid did:key Ed25519 public key."} =
               Crypto.did_key(%{"kty" => "OKP", "crv" => "Ed25519", "x" => 1})

      assert {:error, "Invalid did:key elliptic curve public key."} =
               Crypto.did_key(invalid_ec)

      assert {:error, "Unsupported did:key JWK."} = Crypto.did_key(%{"kty" => "oct"})
    end
  end

  describe "public_key_jwk/1" do
    test "validates multibase and multicodec input" do
      assert {:error, "Unsupported did:key multibase encoding."} =
               Crypto.public_key_jwk("f0123")

      assert {:error, "Invalid did:key fingerprint."} = Crypto.public_key_jwk("z")

      assert {:error, "Invalid did:key base58 fingerprint."} =
               Crypto.public_key_jwk("z0")

      assert {:error, "Invalid did:key multicodec value."} =
               Crypto.public_key_jwk(fingerprint_from_bytes(<<0x80>>))

      assert {:error, "Unsupported did:key public key type."} =
               Crypto.public_key_jwk(fingerprint(1, <<1, 2, 3>>))
    end

    test "decodes Ed25519 keys and rejects invalid key lengths" do
      key = :binary.copy(<<7>>, 32)
      encoded_key = Base.url_encode64(key, padding: false)

      assert {:ok,
              %{
                "kty" => "OKP",
                "crv" => "Ed25519",
                "x" => ^encoded_key
              }} = Crypto.public_key_jwk(fingerprint(0xED, key))

      assert {:error, "Unsupported did:key public key type."} =
               Crypto.public_key_jwk(fingerprint(0xED, <<1>>))
    end

    test "decodes compressed and uncompressed P-256 keys" do
      assert {:ok, %{"kty" => "EC", "crv" => "P-256", "x" => x, "y" => y}} =
               Crypto.public_key_jwk(
                 fingerprint(0x1200, <<4, p256_x()::binary, p256_y()::binary>>)
               )

      assert Base.url_decode64!(x, padding: false) == p256_x()
      assert Base.url_decode64!(y, padding: false) == p256_y()

      prefix = if rem(:binary.decode_unsigned(p256_y()), 2) == 0, do: 2, else: 3

      assert {:ok, %{"kty" => "EC", "crv" => "P-256", "x" => ^x, "y" => ^y}} =
               Crypto.public_key_jwk(fingerprint(0x1200, <<prefix, p256_x()::binary>>))

      alternate_prefix = if prefix == 2, do: 3, else: 2

      assert {:ok, %{"kty" => "EC", "crv" => "P-256", "x" => ^x, "y" => alternate_y}} =
               Crypto.public_key_jwk(fingerprint(0x1200, <<alternate_prefix, p256_x()::binary>>))

      refute alternate_y == y
    end

    test "decodes compressed and uncompressed secp256k1 keys" do
      assert {:ok, %{"kty" => "EC", "crv" => "secp256k1", "x" => x, "y" => y}} =
               Crypto.public_key_jwk(
                 fingerprint(
                   0xE7,
                   <<4, secp256k1_x()::binary, secp256k1_y()::binary>>
                 )
               )

      prefix = if rem(:binary.decode_unsigned(secp256k1_y()), 2) == 0, do: 2, else: 3

      assert {:ok, %{"kty" => "EC", "crv" => "secp256k1", "x" => ^x, "y" => ^y}} =
               Crypto.public_key_jwk(fingerprint(0xE7, <<prefix, secp256k1_x()::binary>>))

      assert {:error, "Invalid did:key elliptic curve public key."} =
               Crypto.public_key_jwk(fingerprint(0xE7, <<4, 1, 2, 3>>))
    end

    test "decodes PKCS#1 and SubjectPublicKeyInfo RSA keys" do
      {:RSAPrivateKey, _, modulus, exponent, _, _, _, _, _, _, _} =
        :public_key.generate_key({:rsa, 512, 65_537})

      public_key = {:RSAPublicKey, modulus, exponent}
      pkcs1 = :public_key.der_encode(:RSAPublicKey, public_key)

      {:SubjectPublicKeyInfo, spki, :not_encrypted} =
        :public_key.pem_entry_encode(:SubjectPublicKeyInfo, public_key)

      expected = %{
        "kty" => "RSA",
        "n" => modulus |> :binary.encode_unsigned() |> Base.url_encode64(padding: false),
        "e" => exponent |> :binary.encode_unsigned() |> Base.url_encode64(padding: false)
      }

      assert {:ok, ^expected} = Crypto.public_key_jwk(fingerprint(0x1205, pkcs1))
      assert {:ok, ^expected} = Crypto.public_key_jwk(fingerprint(0x1205, spki))

      assert {:error, "Invalid did:key RSA public key."} =
               Crypto.public_key_jwk(fingerprint(0x1205, <<1, 2, 3>>))
    end

    test "validates JWK-JCS payloads" do
      assert {:error, "Invalid did:key JWK public key."} =
               Crypto.public_key_jwk(fingerprint(@jwk_jcs_public_key_code, "not-json"))

      assert {:error, "Invalid did:key JWK public key."} =
               Crypto.public_key_jwk(
                 fingerprint(@jwk_jcs_public_key_code, Jason.encode!(%{"kty" => "oct"}))
               )
    end
  end

  defp rsa_jwk do
    {_type, jwk} =
      JOSE.JWK.generate_key({:rsa, 512, 65_537})
      |> JOSE.JWK.to_public()
      |> JOSE.JWK.to_map()

    jwk
  end

  defp ec_jwk(curve, x, y) do
    %{
      "kty" => "EC",
      "crv" => curve,
      "x" => Base.url_encode64(x, padding: false),
      "y" => Base.url_encode64(y, padding: false)
    }
  end

  defp p256_x,
    do: Base.decode16!("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296")

  defp p256_y,
    do: Base.decode16!("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")

  defp secp256k1_x,
    do: Base.decode16!("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")

  defp secp256k1_y,
    do: Base.decode16!("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")

  defp fingerprint(code, key), do: fingerprint_from_bytes(encode_varint(code) <> key)

  defp fingerprint_from_bytes(bytes), do: "z" <> base58btc_encode(bytes)

  defp encode_varint(value) when value < 0x80, do: <<value>>
  defp encode_varint(value), do: <<(value &&& 0x7F) ||| 0x80>> <> encode_varint(value >>> 7)

  defp base58btc_encode(bytes) do
    alphabet = ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    leading_zeroes =
      bytes
      |> :binary.bin_to_list()
      |> Enum.take_while(&(&1 == 0))
      |> length()

    encoded =
      bytes
      |> :binary.decode_unsigned()
      |> encode_base58_integer(alphabet, [])

    :binary.copy("1", leading_zeroes) <> encoded
  end

  defp encode_base58_integer(0, _alphabet, []), do: ""
  defp encode_base58_integer(0, _alphabet, chars), do: List.to_string(chars)

  defp encode_base58_integer(integer, alphabet, chars) do
    encode_base58_integer(
      div(integer, 58),
      alphabet,
      [Enum.at(alphabet, rem(integer, 58)) | chars]
    )
  end
end
