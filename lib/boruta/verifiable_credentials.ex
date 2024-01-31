defmodule Boruta.VerifiableCredentials do
  @moduledoc false

  alias Boruta.Config
  alias Boruta.Oauth
  alias Boruta.Oauth.ResourceOwner
  alias ExJsonSchema.Schema
  alias ExJsonSchema.Validator.Error.BorutaFormatter

  @authorization_details_schema %{
    "type" => "array",
    "items" => %{
      "type" => "object",
      "properties" => %{
        "type" => %{"type" => "string", "pattern" => "^openid_credential$"},
        "format" => %{"type" => "string"},
        "credential_definition" => %{
          "type" => "object",
          "properties" => %{
            "type" => %{
              "type" => "array",
              "items" => %{"type" => "string"}
            }
          }
        }
      },
      "required" => ["type", "format"]
    }
  }

  @proof_schema %{
                  "type" => "object",
                  "properties" => %{
                    "proof_type" => %{"type" => "string", "pattern" => "^jwt$"},
                    "jwt" => %{"type" => "string"}
                  },
                  "required" => ["proof_type", "jwt"]
                }
                |> Schema.resolve()

  defmodule Token do
    @moduledoc false

    use Joken.Config

    def token_config, do: %{}
  end

  @spec issue_verifiable_credential(
          resource_owner :: ResourceOwner.t(),
          credential_params :: map(),
          client :: Boruta.Oauth.Client.t(),
          default_credential_configuration :: map()
        ) :: {:ok, map()} | {:error, String.t()}
  def issue_verifiable_credential(
        resource_owner,
        credential_params,
        client,
        default_credential_configuration
      ) do
    proof = credential_params["proof"]

    credential_configuration =
      case resource_owner.sub do
        "did:" <> _key -> default_credential_configuration
        _ -> resource_owner.credential_configuration
      end

    with {_credential_identifier, credential_configuration} <-
           Enum.find(credential_configuration, fn {_identifier, configuration} ->
             Enum.empty?(configuration[:types] -- credential_params["types"])
           end),
         {:ok, proof} <- validate_proof_format(proof),
         :ok <- validate_headers(proof["jwt"]),
         :ok <- validate_claims(proof["jwt"]),
         :ok <- validate_signature(proof["jwt"]),
         {:ok, claims} <-
           extract_credential_claims(
             resource_owner,
             credential_configuration
           ),
         {:ok, credential} <-
           generate_credential(
             claims,
             credential_configuration,
             proof["jwt"],
             client,
             credential_configuration[:format]
           ) do
      credential = %{
        format: credential_configuration[:format],
        credential: credential
      }

      {:ok, credential}
    else
      nil -> {:error, "Credential not found."}
      error -> error
    end
  end

  @spec validate_authorization_details(authorization_details :: String.t()) ::
          :ok | {:error, reason :: String.t()}
  def validate_authorization_details(authorization_details) do
    with {:ok, authorization_details} <- Jason.decode(authorization_details),
         :ok <-
           ExJsonSchema.Validator.validate(
             @authorization_details_schema,
             authorization_details,
             error_formatter: BorutaFormatter
           ) do
      :ok
    else
      {:error, errors} when is_list(errors) ->
        {:error, "authorization_details validation failed. " <> Enum.join(errors, " ")}

      {:error, error} ->
        {:error, "authorization_details validation failed. #{inspect(error)}"}
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
          case alg =~ ~r/^(RS|ES)/ do
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
    case Joken.peek_header(jwt) do
      {:ok, %{"alg" => alg} = headers} ->
        case(extract_key(headers)) do
          {:did, _did} ->
            # TODO verify signature from did
            :ok

          {:jwk, jwk} ->
            signer =
              Joken.Signer.create(alg, %{"pem" => jwk |> JOSE.JWK.from_map() |> JOSE.JWK.to_pem()})

            case Token.verify(jwt, signer) do
              {:ok, _claims} ->
                :ok

              _ ->
                {:error, "Bad proof signature"}
            end
        end

      _ ->
        {:error, "Proof has not been signed with provided material."}
    end
  rescue
    _ ->
      {:error, "Proof has not been signed with provided material."}
  end

  defp validate_signature(_jwt), do: {:error, "Proof does not contain a valid JWT."}

  defp extract_credential_claims(resource_owner, credential_configuration) do
    claims =
      credential_configuration[:claims]
      |> Enum.map(fn
        %{"name" => name, "pointer" => pointer} ->
          {name, get_in(resource_owner.extra_claims, String.split(pointer, "."))}

        attribute when is_binary(attribute) ->
          {attribute, get_in(resource_owner.extra_claims, String.split(attribute, "."))}
      end)
      |> Enum.into(%{})

    {:ok, claims}
  end

  defp generate_credential(claims, credential_configuration, proof, client, format)
       when format in ["jwt_vc", "jwt_vc_json"] do
    # _sd = claims
    #       |> Enum.map(fn {name, value} ->
    #   [SecureRandom.hex(), name, value]
    # end)
    # # NOTE no space in disclosure array
    # |> Enum.map(&Jason.encode!/1)
    # |> Enum.map(&Base.url_encode64(&1, padding: false))
    # |> Enum.map(fn disclosure ->
    #   :crypto.hash(:sha256, disclosure) |> Base.url_encode64(padding: false)
    # end)
    # |> dbg
    signer =
      Joken.Signer.create(
        client.id_token_signature_alg,
        %{"pem" => client.private_key},
        %{
          "typ" => "JWT",
          "kid" => Oauth.Client.Crypto.kid_from_private_key(client.private_key)
        }
      )

    sub =
      case Joken.peek_header(proof) do
        {:ok, headers} ->
          case(extract_key(headers)) do
            {_type, key} -> key
          end
      end

    claims = %{
      "sub" => sub,
      # TODO store credential
      "jti" => Config.issuer() <> "/credentials/#{SecureRandom.uuid()}",
      "iss" => Config.issuer(),
      "iat" => :os.system_time(:seconds),
      # TODO get exp from configuration
      "exp" => :os.system_time(:seconds) + 3600 * 24 * 365 * 3,
      # TODO implement c_nonce
      "nonce" => "boruta",
      "vc" => %{
        # TODO get context from configuration
        "@context" => [
          "https://www.w3.org/2018/credentials/v1"
        ],
        "type" => credential_configuration[:types],
        "credentialSubject" => claims
      }
    }

    credential = Token.generate_and_sign!(claims, signer)

    {:ok, credential}
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
