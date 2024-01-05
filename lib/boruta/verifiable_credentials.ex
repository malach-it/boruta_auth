defmodule Boruta.VerifiableCredentials do
  @moduledoc false

  alias Boruta.Oauth.ResourceOwner
  alias ExJsonSchema.Schema
  alias ExJsonSchema.Validator.Error.BorutaFormatter

  @proof_schema %{
                  "type" => "object",
                  "properties" => %{
                    "type" => %{"type" => "string", "pattern" => "^jwt$"},
                    "proof" => %{"type" => "string"}
                  },
                  "required" => ["type", "proof"]
                }
                |> Schema.resolve()

  defmodule Token do
    @moduledoc false

    use Joken.Config

    def token_config, do: %{}
  end

  @spec issue_verifiable_credential(
          resource_owner :: ResourceOwner.t(),
          credential_identifier :: String.t(),
          # TODO have a credential_configuration struct
          credential_configuration :: %{
            claims: %{
              String.t() => list(String.t())
            },
            signature_private_key_pem: String.t()
          },
          proof :: map()
        ) :: map()
  def issue_verifiable_credential(
        resource_owner,
        credential_identifier,
        credential_configuration,
        proof
      ) do
    with {:ok, proof} <- validate_proof_format(proof),
         :ok <- validate_headers(proof["proof"]),
         :ok <- validate_claims(proof["proof"]),
         :ok <- validate_signature(proof["proof"]),
         {:ok, claims} <-
           extract_credential_claims(
             resource_owner,
             credential_configuration,
             credential_identifier
           ),
         {:ok, jwt} <- generate_credential(claims, credential_configuration, proof["proof"]) do
      claims
    end
  end

  defp validate_proof_format(proof) do
    case ExJsonSchema.Validator.validate(
           @proof_schema,
           proof,
           error_formatter: BorutaFormatter
         ) do
      :ok ->
        {:ok, proof}

      {:error, errors} ->
        {:error, "Proof validation failed. " <> Enum.join(errors, " ")}
    end
  end

  defp validate_headers(jwt) when is_binary(jwt) do
    case Joken.peek_header(jwt) do
      {:ok, %{"alg" => alg, "typ" => typ} = headers} ->
        alg_check =
          case alg =~ ~r/^RS/ do
            true ->
              :ok

            false ->
              "Proof JWT must be asymetrically signed"
          end

        typ_check =
          case typ =~ ~r/^openid4vci-proof\+jwt$/ do
            true ->
              :ok

            false ->
              "Proof JWT must have `openid4vci-proof+jwt` typ header"
          end

        key_check =
          case extract_key(headers) do
            {:error, reason} ->
              reason

            _ ->
              :ok
          end

        do_validate_headers(alg_check, typ_check, key_check)

      _ ->
        {:error, "Proof does not contain valid JWT headers, `alg` and `typ` are required."}
    end
  end

  defp validate_headers(_jwt), do: {:error, "Proof does not contain a valid JWT."}

  defp validate_claims(jwt) when is_binary(jwt) do
    case Joken.peek_claims(jwt) do
      {:ok, %{"aud" => _aud, "iat" => _iat}} ->
        :ok

      _ ->
        {:error, "Proof does not contain valid JWT claims, `aud` and `iat` claims are required."}
    end
  end

  defp validate_claims(_jwt), do: {:error, "Proof does not contain a valid JWT."}

  defp validate_signature(jwt) when is_binary(jwt) do
    with {:ok, %{"alg" => alg} = headers} <- Joken.peek_header(jwt),
         {:jwk, jwk} <- extract_key(headers),
         signer <-
           Joken.Signer.create(alg, %{"pem" => jwk |> JOSE.JWK.from_map() |> JOSE.JWK.to_pem()}),
         {:ok, _claims} <- Token.verify(jwt, signer) do
      :ok
    else
      _ ->
        {:error, "Proof has not been signed with provided material."}
    end
  rescue
    _ ->
      {:error, "Proof has not been signed with provided material."}
  end

  defp validate_signature(_jwt), do: {:error, "Proof does not contain a valid JWT."}

  defp extract_credential_claims(resource_owner, credential_configuration, credential_identifier) do
    claims =
      Enum.map(credential_configuration[:claims][credential_identifier] || [], fn attribute ->
        {attribute, resource_owner.extra_claims[attribute]}
      end)
      |> Enum.into(%{})

    {:ok, claims}
  end

  defp generate_credential(claims, credential_configuration, proof) do
    _sd = claims
          |> Enum.map(fn {name, value} ->
      [SecureRandom.hex(), name, value]
    end)
    # NOTE no space in disclosure array
    |> Enum.map(&Jason.encode!/1)
    |> Enum.map(&Base.url_encode64(&1, padding: false))
    |> Enum.map(fn disclosure ->
      :crypto.hash(:sha256, disclosure) |> Base.url_encode64(padding: false)
    end)
    |> dbg
    # signer =
    #   Joken.Signer.create("RS256", %{"pem" => private_key_fixture()}, %{
    #     "jwk" => public_jwk,
    #     "typ" => "openid4vci-proof+jwt"
    #   })
  end

  defp extract_key(%{"kid" => did}), do: {:did, did}
  defp extract_key(%{"jwk" => jwk}), do: {:jwk, jwk}
  defp extract_key(_headers), do: {:error, "No proof key material found in JWT headers"}

  defp do_validate_headers(alg_check, typ_check, key_check) do
    case Enum.reject(
           [
             alg_check,
             typ_check,
             key_check
           ],
           fn
             :ok -> true
             _ -> false
           end
         ) do
      [] ->
        :ok

      errors ->
        {:error, Enum.join(errors, ", ") <> "."}
    end
  end
end
