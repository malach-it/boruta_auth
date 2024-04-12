defmodule Boruta.VerifiableCredentials do
  defmodule Hotp do
    @moduledoc """
    Implements HOTP generation as described in the IETF RFC
    [HOTP: An HMAC-Based One-Time Password Algorithm](https://www.ietf.org/rfc/rfc4226.txt)
    > This implementation defaults to 6 digits using the sha1 algorithm as hashing function
    """

    import Bitwise

    @hmac_algorithm :sha
    @digits 6

    @spec generate_hotp(secret :: String.t(), counter :: integer()) :: hotp :: String.t()
    def generate_hotp(secret, counter) do
      # Step 1: Generate an HMAC-SHA-1 value
      hmac_result = :crypto.mac(:hmac, @hmac_algorithm, secret, <<counter::size(64)>>)

      # Step 2: Dynamic truncation
      truncated_hash = truncate_hash(hmac_result)

      # Step 3: Compute HOTP value (6-digit OTP)
      hotp = truncated_hash |> rem(10 ** @digits)

      format_hotp(hotp)
    end

    defp truncate_hash(hmac_value) do
      # NOTE the folowing hard coded values are part of the specification
      offset = :binary.at(hmac_value, 19) &&& 0xF

      with <<_::size(1), result::size(31)>> <- :binary.part(hmac_value, offset, 4) do
        result
      end
    end

    defp format_hotp(hotp) do
      Integer.to_string(hotp, 16)
    end
  end
  @moduledoc false

  import Boruta.Config, only: [universalresolver_base_url: 0]

  alias Boruta.Config
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.ResourceOwner
  alias ExJsonSchema.Schema
  alias ExJsonSchema.Validator.Error.BorutaFormatter

  @public_client_did "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbowkrd8N32k1hMP7589MHcyNK7C5CYhRki8Qk28SFfQ3S4UECo7cet1N7AMxbyNRdv13955RPTWUk8EnJtBCpP1pDB9gvK1x6zBZArptWqYFC2t7kNA3KXVMH53d9W3QWep"
  @individual_claim_default_expiration 3600 * 24 * 30 * 365 * 120 # 10 years
  @validity_shift 55

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

    # TODO filter from resource owner authorization details
    with {credential_identifier, credential_configuration} <-
           Enum.find(credential_configuration, fn {_identifier, configuration} ->
             case configuration[:version] do
               "11" ->
                 Enum.empty?(configuration[:types] -- credential_params["types"])

               "13" ->
                 Enum.member?(configuration[:types], credential_params["credential_identifier"])
             end
           end),
         {:ok, proof} <- validate_proof_format(proof),
         :ok <- validate_headers(proof["jwt"]),
         :ok <- validate_claims(proof["jwt"]),
         {:ok, claims} <-
           extract_credential_claims(
             resource_owner,
             credential_configuration
           ),
         {:ok, jwk, _claims} <- validate_signature(proof["jwt"]),
         {:ok, credential} <-
           generate_credential(
             claims,
             {credential_identifier, credential_configuration},
             {jwk, proof["jwt"]},
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

  @spec validate_signature(jwt :: String.t()) ::
          {:ok, claims :: map()} | {:error, reason :: String.t()}
  def validate_signature(jwt) when is_binary(jwt) do
    case Joken.peek_header(jwt) do
      {:ok, %{"alg" => alg} = headers} ->
        verify_jwt(extract_key(headers), alg, jwt)

      error ->
        {:error, inspect(error)}
    end
  rescue
    error ->
      {:error, inspect(error)}
  end

  def validate_signature(_jwt), do: {:error, "Proof does not contain a valid JWT."}

  defp verify_jwt({:did, did}, alg, jwt) do
    resolver_url = "#{universalresolver_base_url()}/1.0/identifiers/#{did}"

    case Finch.build(:get, resolver_url) |> Finch.request(OpenIDHttpClient) do
      {:ok, %Finch.Response{body: body, status: 200}} ->
        %{"didDocument" => %{"verificationMethod" => [%{"publicKeyJwk" => jwk}]}} =
          Jason.decode!(body)

        signer = Joken.Signer.create(alg, %{"pem" => JOSE.JWK.from_map(jwk) |> JOSE.JWK.to_pem()})

        case Client.Token.verify(jwt, signer) do
          {:ok, claims} -> {:ok, jwk, claims}
          {:error, error} -> {:error, inspect(error)}
        end

      {:ok, %Finch.Response{body: body}} ->
        {:error, body}

      _ ->
        {:error, "Could not resolve did."}
    end
  end

  defp verify_jwt({:jwk, jwk}, alg, jwt) do
    signer = Joken.Signer.create(alg, %{"pem" => jwk |> JOSE.JWK.from_map() |> JOSE.JWK.to_pem()})

    case Token.verify(jwt, signer) do
      {:ok, claims} ->
        {:ok, jwk, claims}

      _ ->
        {:error, "Bad proof signature"}
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

  defp generate_credential(claims, {_credential_identifier, credential_configuration}, {jwk, proof}, client, format)
       when format in ["jwt_vc_json"] do
    signer =
      Joken.Signer.create(
        client.id_token_signature_alg,
        %{"pem" => client.private_key},
        %{
          "typ" => "JWT",
          "kid" => Client.Crypto.kid_from_private_key(client.private_key)
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
      "exp" => :os.system_time(:seconds) + credential_configuration[:time_to_live],
      # TODO implement c_nonce
      "nonce" => "boruta",
      "vc" => %{
        # TODO get context from configuration
        "@context" => [
          "https://www.w3.org/2018/credentials/v1"
        ],
        "type" => credential_configuration[:types],
        "credentialSubject" => claims
        |> Enum.map(fn {name, {claim, _expiration}} -> {name, claim} end)
        |> Enum.into(%{})
      },
      "cnf" => %{
        "jwk" => jwk
      }
    }

    credential = Token.generate_and_sign!(claims, signer)

    {:ok, credential}
  end

  # https://www.w3.org/TR/vc-data-model-2.0/
  defp generate_credential(claims, {credential_identifier, credential_configuration}, {jwk, proof}, client, format)
       when format in ["jwt_vc"] do
    signer =
      Joken.Signer.create(
        client.id_token_signature_alg,
        %{"pem" => client.private_key},
        %{
          "typ" => "JWT",
          # TODO craft ebsi compliant dids
          "kid" => @public_client_did
        }
      )

    sub =
      case Joken.peek_header(proof) do
        {:ok, headers} ->
          case(extract_key(headers)) do
            {_type, key} -> key
          end
      end

    credential_id = SecureRandom.uuid()
    claims = %{
      "@context" => [
        "https://www.w3.org/ns/credentials/v2",
        "https://www.w3.org/ns/credentials/examples/v2"
      ],
      # TODO store credential
      "id" => Config.issuer() <> "/credentials/#{credential_id}",
      "type" => credential_configuration[:types],
      "issuer" => Config.issuer(),
      "validFrom" => DateTime.utc_now() |> DateTime.to_iso8601(),
      "credentialSubject" => %{
        "id" => sub,
        # TODO craft ebsi compliant dids
        credential_identifier => claims
        |> Enum.map(fn {name, {claim, _expiration}} -> {name, claim} end)
        |> Enum.into(%{})
        |> Map.put("id", @public_client_did)
      },
      "cnf" => %{
        "jwk" => jwk
      }
    }

    credential = Token.generate_and_sign!(claims, signer)

    {:ok, credential}
  end

  defp generate_credential(claims, {_credential_identifier, credential_configuration}, {jwk, proof}, client, format)
       when format in ["vc+sd-jwt"] do
    signer =
      Joken.Signer.create(
        client.id_token_signature_alg,
        %{"pem" => client.private_key},
        %{
          "typ" => "JWT",
          "kid" => Client.Crypto.kid_from_private_key(client.private_key)
        }
      )

    sub =
      case Joken.peek_header(proof) do
        {:ok, headers} ->
          case(extract_key(headers)) do
            {_type, key} -> key
          end
      end

    claims_with_salt =
      Enum.map(claims, fn {name, {value, expiration}} ->
        secret = SecureRandom.hex()
        hotp = Hotp.generate_hotp(client.private_key, div(:os.system_time(:seconds), expiration) + @validity_shift)
        salt = "#{secret}~#{hotp}"
        {{name, value}, salt}
      end)

    disclosures =
      claims_with_salt
      |> Enum.map(fn {{name, value}, salt} ->
        [salt, name, value]
      end)

    sd =
      disclosures
      # NOTE no space in disclosure array
      |> Enum.map(fn disclosure -> Jason.encode!(disclosure) end)
      |> Enum.map(fn disclosure -> Base.url_encode64(disclosure, padding: false) end)
      |> Enum.map(fn disclosure ->
        :crypto.hash(:sha256, disclosure) |> Base.url_encode64(padding: false)
      end)

    claims = %{
      "sub" => sub,
      "iss" => Config.issuer(),
      "iat" => :os.system_time(:seconds),
      # TODO get exp from configuration
      "exp" => :os.system_time(:seconds) + credential_configuration[:time_to_live],
      # TODO implement c_nonce
      "nonce" => "boruta",
      "_sd" => sd,
      "cnf" => %{
        "jwk" => jwk
      }
    }

    credential = Token.generate_and_sign!(claims, signer)

    tokens =
      [credential] ++
        (disclosures
         |> Enum.map(&Jason.encode!/1)
         |> Enum.map(&Base.url_encode64(&1, padding: false)))

    {:ok, Enum.join(tokens, "~")}
  end

  defp generate_credential(_claims, _credential_configuration, _proof, _client, _format),
    do: {:error, "Unkown format."}

  defp extract_credential_claims(resource_owner, credential_configuration) do
    claims =
      credential_configuration[:claims]
      |> Enum.map(fn
        %{"name" => name, "pointer" => pointer} = claim ->
          {name, {get_in(resource_owner.extra_claims, String.split(pointer, ".")), String.to_integer(claim["expiration"]) || @individual_claim_default_expiration}}

        attribute when is_binary(attribute) ->
          {attribute, {get_in(resource_owner.extra_claims, String.split(attribute, ".")), @individual_claim_default_expiration}}
      end)
      |> Enum.into(%{})

    {:ok, claims}
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
