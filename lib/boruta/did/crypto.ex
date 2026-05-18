defmodule Boruta.Did.Crypto do
  @moduledoc false

  import Bitwise

  @base58_alphabet ~c"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  @base58_indexes @base58_alphabet |> Enum.with_index() |> Map.new()

  @ed25519_public_key_code 0xED
  @p256_public_key_code 0x1200
  @secp256k1_public_key_code 0xE7
  @rsa_public_key_code 0x1205

  @p256_prime 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
  @p256_a @p256_prime - 3
  @p256_b 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
  @secp256k1_prime 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  @secp256k1_a 0
  @secp256k1_b 7

  @spec public_key_jwk(fingerprint :: String.t()) ::
          {:ok, jwk :: map()} | {:error, reason :: String.t()}
  def public_key_jwk(fingerprint) do
    with {:ok, public_key_bytes} <- decode_multibase(fingerprint),
         {:ok, key_code, key_bytes} <- decode_multicodec(public_key_bytes) do
      public_key_jwk(key_code, key_bytes)
    end
  end

  defp decode_multibase("z" <> base58_key), do: base58btc_decode(base58_key)

  defp decode_multibase(_fingerprint),
    do: {:error, "Unsupported did:key multibase encoding."}

  defp base58btc_decode(""), do: {:error, "Invalid did:key fingerprint."}

  defp base58btc_decode(base58_key) do
    chars = String.to_charlist(base58_key)

    with {:ok, integer} <- decode_base58_integer(chars) do
      leading_zero_count = chars |> Enum.take_while(&(&1 == ?1)) |> length()
      decoded = if integer == 0, do: <<>>, else: :binary.encode_unsigned(integer)

      {:ok, :binary.copy(<<0>>, leading_zero_count) <> decoded}
    end
  end

  defp decode_base58_integer(chars) do
    Enum.reduce_while(chars, {:ok, 0}, fn char, {:ok, integer} ->
      case @base58_indexes[char] do
        nil -> {:halt, {:error, "Invalid did:key base58 fingerprint."}}
        value -> {:cont, {:ok, integer * 58 + value}}
      end
    end)
  end

  defp decode_multicodec(bytes), do: decode_multicodec(bytes, 0, 0)

  defp decode_multicodec(<<>>, _value, _shift),
    do: {:error, "Invalid did:key multicodec value."}

  defp decode_multicodec(<<byte, rest::binary>>, value, shift) do
    next_value = value ||| (byte &&& 0x7F) <<< shift

    if (byte &&& 0x80) == 0 do
      {:ok, next_value, rest}
    else
      decode_multicodec(rest, next_value, shift + 7)
    end
  end

  defp public_key_jwk(@ed25519_public_key_code, <<x::binary-size(32)>>) do
    {:ok,
     %{
       "kty" => "OKP",
       "crv" => "Ed25519",
       "x" => base64url(x)
     }}
  end

  defp public_key_jwk(@p256_public_key_code, public_key) do
    ec_public_key_jwk(public_key, "P-256", @p256_prime, @p256_a, @p256_b, 32)
  end

  defp public_key_jwk(@secp256k1_public_key_code, public_key) do
    ec_public_key_jwk(public_key, "secp256k1", @secp256k1_prime, @secp256k1_a, @secp256k1_b, 32)
  end

  defp public_key_jwk(@rsa_public_key_code, public_key) do
    with {:ok, modulus, exponent} <- decode_rsa_public_key(public_key) do
      {:ok,
       %{
         "kty" => "RSA",
         "n" => modulus |> :binary.encode_unsigned() |> base64url(),
         "e" => exponent |> :binary.encode_unsigned() |> base64url()
       }}
    end
  end

  defp public_key_jwk(_key_code, _public_key),
    do: {:error, "Unsupported did:key public key type."}

  defp ec_public_key_jwk(<<4, x::binary-size(32), y::binary-size(32)>>, crv, _prime, _a, _b, 32) do
    {:ok,
     %{
       "kty" => "EC",
       "crv" => crv,
       "x" => base64url(x),
       "y" => base64url(y)
     }}
  end

  defp ec_public_key_jwk(<<prefix, x::binary-size(32)>>, crv, prime, a, b, 32)
       when prefix in [2, 3] do
    x_int = :binary.decode_unsigned(x)
    y_squared = positive_rem(mod_pow(x_int, 3, prime) + a * x_int + b, prime)
    y = mod_sqrt(y_squared, prime)

    y =
      if rem(y, 2) == rem(prefix, 2) do
        y
      else
        prime - y
      end

    {:ok,
     %{
       "kty" => "EC",
       "crv" => crv,
       "x" => base64url(x),
       "y" => y |> :binary.encode_unsigned() |> pad_unsigned(32) |> base64url()
     }}
  end

  defp ec_public_key_jwk(_public_key, _crv, _prime, _a, _b, _size),
    do: {:error, "Invalid did:key elliptic curve public key."}

  defp decode_rsa_public_key(public_key) do
    case safe_der_decode(:RSAPublicKey, public_key) do
      {:ok, {:RSAPublicKey, modulus, exponent}} ->
        {:ok, modulus, exponent}

      _ ->
        decode_subject_public_key_info(public_key)
    end
  end

  defp decode_subject_public_key_info(public_key) do
    with {:ok, {:SubjectPublicKeyInfo, _algorithm, rsa_public_key}} <-
           safe_der_decode(:SubjectPublicKeyInfo, public_key),
         {:ok, {:RSAPublicKey, modulus, exponent}} <-
           safe_der_decode(:RSAPublicKey, rsa_public_key) do
      {:ok, modulus, exponent}
    else
      _ -> {:error, "Invalid did:key RSA public key."}
    end
  end

  defp safe_der_decode(type, der) do
    {:ok, :public_key.der_decode(type, der)}
  rescue
    _ -> {:error, :invalid_der}
  end

  defp base64url(binary), do: Base.url_encode64(binary, padding: false)

  defp pad_unsigned(binary, size) when byte_size(binary) < size do
    :binary.copy(<<0>>, size - byte_size(binary)) <> binary
  end

  defp pad_unsigned(binary, _size), do: binary

  defp mod_sqrt(value, prime), do: mod_pow(value, div(prime + 1, 4), prime)

  defp mod_pow(_base, 0, _modulus), do: 1

  defp mod_pow(base, exponent, modulus) do
    mod_pow(positive_rem(base, modulus), exponent, modulus, 1)
  end

  defp mod_pow(_base, 0, _modulus, result), do: result

  defp mod_pow(base, exponent, modulus, result) when (exponent &&& 1) == 1 do
    mod_pow(
      positive_rem(base * base, modulus),
      exponent >>> 1,
      modulus,
      positive_rem(result * base, modulus)
    )
  end

  defp mod_pow(base, exponent, modulus, result) do
    mod_pow(positive_rem(base * base, modulus), exponent >>> 1, modulus, result)
  end

  defp positive_rem(value, modulus),
    do: value |> rem(modulus) |> Kernel.+(modulus) |> rem(modulus)
end
