defmodule Boruta.VerifiableCredentials do
  defmodule Hotp do
    @moduledoc """
    Implements HOTP generation as described in the IETF RFC
    [HOTP: An HMAC-Based One-Time Password Algorithm](https://www.ietf.org/rfc/rfc4226.txt)
    > This implementation defaults to 6 digits using the sha1 algorithm as hashing function
    """

    import Bitwise

    @hmac_algorithm :sha
    @digits 12

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
      Integer.to_string(hotp, 16) |> String.downcase()
    end
  end

  @moduledoc false

  alias Boruta.Config
  alias Boruta.Did
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Scope
  alias Boruta.Openid.Credential
  alias ExJsonSchema.Schema
  alias ExJsonSchema.Validator.Error.BorutaFormatter

  # @public_client_did "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbrSfZqXLVn\
  # TT5rRw7VCjbapSKSfZEUSekzuBrGZhfwxQTfsNVeUYsX5gH2eJ4LdVt6uctFyJsW76VygayYHiHpwnhGwAombi\
  # RJiimmRTMXUAa49VQ9NWT7PUK2P7VbBy4Bn"
  @individual_claim_default_expiration 3600 * 24 * 365 * 120

  @status_table [
    :valid,
    :suspended,
    :revoked
  ]

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
          token :: Boruta.Oauth.Token.t(),
          default_credential_configuration :: map()
        ) :: {:ok, map()} | {:error, String.t()}
  def issue_verifiable_credential(
        resource_owner,
        credential_params,
        token,
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
           Enum.find(credential_configuration, fn {identifier, configuration} ->
             case configuration[:version] do
               "11" ->
                 Enum.empty?(configuration[:types] -- credential_params["types"]) ||
                   Enum.member?(Scope.split(token.scope), identifier)

               "13" ->
                 Enum.member?(
                   configuration[:types],
                   credential_params["vct"] || credential_params["credential_identifier"]
                 ) ||
                   Enum.member?(Scope.split(token.scope), identifier)
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
             token,
             credential_configuration[:format]
           ) do
      credential = %Credential{
        format: credential_configuration[:format],
        defered: credential_configuration[:defered],
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
          {:ok, jwk ::map(), claims :: map()} | {:error, reason :: String.t()}
  def validate_signature(jwt) when is_binary(jwt) do
    case Joken.peek_header(jwt) do
      {:ok, %{"alg" => alg} = headers} ->
        verify_jwt(extract_key(headers), alg, jwt)

      error ->
        {:error, inspect(error)}
    end
  # rescue
  #   error ->
  #     {:error, inspect(error)}
  end

  def validate_signature(_jwt), do: {:error, "Proof does not contain a valid JWT."}

  defp verify_jwt({:did, did}, alg, jwt) do
    with {:ok, did_document} <- Did.resolve(did),
         %{"verificationMethod" => methods} <- did_document do

        Enum.reduce_while(
          methods,
          {:error, "no did verification method found with did #{did}."},
          fn %{"publicKeyJwk" => jwk}, {:error, errors} ->
            signer =
              Joken.Signer.create(alg, %{"pem" => JOSE.JWK.from_map(jwk) |> JOSE.JWK.to_pem()})

            case Client.Token.verify(jwt, signer) do
              {:ok, claims} -> {:halt, {:ok, jwk, claims}}
              {:error, error} -> {:cont, {:error, errors <> ", #{inspect(error)} with key #{inspect(jwk)}"}}
            end
          end
        )

    else
      {:error, error} ->
        {:error, error}
      did_document ->
        {:error, "Invalid did document: \"#{inspect(did_document)}\""}
    end
  end

  defp verify_jwt({:jwk, jwk}, "EdDSA", jwt) do
    signer = Joken.Signer.create("ES256", %{"pem" => jwk |> JOSE.JWK.from_map() |> JOSE.JWK.to_pem()})

    case Token.verify(jwt, signer) do
      {:ok, claims} ->
        {:ok, jwk, claims}

      _ ->
        {:error, "Bad proof signature"}
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

  defp verify_jwt(error, _alg, _jwt), do: error

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
          case alg =~ ~r/^(RS|ES|EdDSA)/ do
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

  defp generate_credential(
         claims,
         {credential_identifier, credential_configuration},
         {_jwk, proof},
         token,
         format
       )
       when format in ["jwt_vc_json"] do
    client = token.client

    signer =
      Joken.Signer.create(
        client.id_token_signature_alg,
        %{"pem" => client.private_key},
        %{
          "typ" => "JWT",
          "kid" => case client.did do
            nil ->
              Client.Crypto.kid_from_private_key(client.private_key)
            did ->
              did <> "#" <> String.replace(did, "did:key:", "")
          end
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

    now = :os.system_time(:seconds)

    sub = sub |> String.split("#") |> List.first()
    claims = %{
      "sub" => sub,
      # TODO store credential
      "jti" => Config.issuer() <> "/credentials/#{credential_id}",
      "iss" => client.did,
      "nbf" => now,
      "iat" => now,
      "exp" => now + credential_configuration[:time_to_live],
      "nonce" => token.c_nonce,
      "vc" => %{
        "@context" => [
          "https://www.w3.org/2018/credentials/v1"
        ],
        # TODO store credential
        "id" => Config.issuer() <> "/credentials/#{credential_id}",
        "issued" => DateTime.from_unix!(now) |> DateTime.to_iso8601(),
        "issuanceDate" => DateTime.from_unix!(now) |> DateTime.to_iso8601(),
        "type" => credential_configuration[:types],
        "issuer" => client.did,
        "validFrom" => DateTime.from_unix!(now) |> DateTime.to_iso8601(),
        "credentialSubject" => %{
          "id" => sub,
          credential_identifier =>
            claims
            |> Enum.map(fn {name, {claim, _status, _expiration}} -> {name, claim} end)
            |> Enum.into(%{})
            |> Map.put("id", client.did)
        },
        "credentialSchema" => %{
          "id" => "https://api-pilot.ebsi.eu/trusted-schemas-registry/v2/schemas/z3MgUFUkb722uq4x3dv5yAJmnNmzDFeK5UC8x83QoeLJM",
          "type" => "FullJsonSchemaValidator2021"
        }
      }
    }

    credential = Token.generate_and_sign!(claims, signer)

    {:ok, credential}
  end

  # https://www.w3.org/TR/vc-data-model-2.0/
  defp generate_credential(
         claims,
         {credential_identifier, credential_configuration},
         {jwk, proof},
         token,
         format
       )
       when format in ["jwt_vc"] do
    client = token.client

    signer =
      Joken.Signer.create(
        client.id_token_signature_alg,
        %{"pem" => client.private_key},
        %{
          "typ" => "JWT",
          # TODO craft ebsi compliant dids
          "kid" => client.did
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
        credential_identifier =>
          claims
          |> Enum.map(fn {name, {claim, _status, _expiration}} -> {name, claim} end)
          |> Enum.into(%{})
          |> Map.put("id", client.did)
      },
      "cnf" => %{
        "jwk" => jwk
      }
    }

    credential = Token.generate_and_sign!(claims, signer)

    {:ok, credential}
  end

  defp generate_credential(
         claims,
         {_credential_identifier, credential_configuration},
         {jwk, proof},
         token,
         format
       )
       when format in ["vc+sd-jwt"] do
    client = token.client

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
      Enum.map(claims, fn {name, {value, status, ttl}} ->
        {{name, value}, generate_sd_salt(client.private_key, ttl, String.to_atom(status))}
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
      "nonce" => token.c_nonce,
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

    {:ok, Enum.join(tokens, "~") <> "~"}
  end

  defp generate_credential(_claims, _credential_configuration, _proof, _client, _format),
    do: {:error, "Unkown format."}

  def generate_sd_salt(secret, ttl, status) do
    iat =
      :os.system_time(:microsecond)
      |> :binary.encode_unsigned()
      |> :binary.bin_to_list()
      |> :string.right(7, 0)

    padded_ttl =
      :binary.encode_unsigned(ttl)
      |> :binary.bin_to_list()
      |> :string.right(4, 0)

    status_list =
      iat ++
        padded_ttl

    salt =
      status_list
      |> to_string()
      |> Base.url_encode64(padding: false)

    hotp =
      Hotp.generate_hotp(
        secret,
        div(:os.system_time(:seconds), ttl) + shift(status)
      )

    "#{salt}~#{hotp}"
  end

  def verify_salt(secret, salt) do
    [status_list, hotp] = String.split(salt, "~")

    %{ttl: ttl} =
      status_list
      |> Base.url_decode64!(padding: false)
      |> to_charlist()
      |> parse_statuslist()

    Enum.reduce_while(@status_table, :expired, fn status, acc ->
      case hotp ==
             Hotp.generate_hotp(
               secret,
               div(:os.system_time(:seconds), ttl) + shift(status)
             ) do
        true -> {:halt, status}
        false -> {:cont, acc}
      end
    end)
  rescue
    _ -> :invalid
  end

  def parse_statuslist(statuslist) do
    parse_statuslist(statuslist, {0, %{ttl: [], memory: []}})
  end

  def parse_statuslist([], {_index, result}), do: result

  def parse_statuslist([_char | t], {index, acc}) when index < 7 do
    parse_statuslist(t, {index + 1, acc})
  end

  def parse_statuslist([char | t], {index, acc}) when index < 10 do
    acc = Map.put(acc, :memory, acc[:memory] ++ [char])
    parse_statuslist(t, {index + 1, acc})
  end

  def parse_statuslist([char | t], {index, acc}) when index == 10 do
    acc =
      acc
      |> Map.put(
        :ttl,
        (acc[:memory] ++ [char])
        |> :erlang.list_to_binary()
        |> :binary.decode_unsigned()
      )
      |> Map.put(:memory, [])

    parse_statuslist(t, {index + 1, acc})
  end

  defp extract_credential_claims(resource_owner, credential_configuration) do
    claims =
      credential_configuration[:claims]
      |> Enum.map(fn
        %{"name" => name, "pointer" => pointer} = claim ->
          resource_owner_claim =
            case get_in(resource_owner.extra_claims, String.split(pointer, ".")) do
              value when is_binary(value) -> %{"value" => value}
              claim -> claim
            end

          {name,
           {resource_owner_claim["value"], resource_owner_claim["status"] || "valid",
            (claim["expiration"] && String.to_integer(claim["expiration"])) ||
              @individual_claim_default_expiration}}

        attribute when is_binary(attribute) ->
          {attribute,
           {get_in(resource_owner.extra_claims, String.split(attribute, ".")), "valid",
            @individual_claim_default_expiration}}
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

  def shift(status) do
    Atom.to_string(status)
    |> :binary.decode_unsigned()
  end
end
