defmodule Boruta.Openid.VerifiablePresentations do
  # TODO add typespec definitions for public functions
  @moduledoc false

  defmodule Token do
    @moduledoc false

    use Joken.Config

    def token_config, do: %{}
  end

  alias Boruta.Did
  alias Boruta.HttpClient
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Scope
  alias Boruta.Openid.Json.Schema
  alias Boruta.Openid.VerifiableCredentials.Status
  alias ExJsonSchema.Validator.Error.BorutaFormatter

  # TODO perform client metadata checks
  def check_client_metadata(_client_metadata), do: :ok

  def response_types(
        response_type,
        scope,
        presentation_configuration,
        request_presentation_definition \\ nil
      ) do
    response_types = String.split(response_type, " ")

    case response_types do
      ["code" | _rest] ->
        response_types

      ["id_token" | _rest] ->
        response_types

      ["vp_token" | rest] ->
        has_presentation_configuration? =
          Enum.any?(Map.keys(presentation_configuration), fn presentation_identifier ->
            Enum.member?(Scope.split(scope), presentation_identifier)
          end)

        case has_presentation_configuration? || not is_nil(request_presentation_definition) do
          true -> String.split(response_type, " ")
          false -> ["id_token" | rest]
        end

      _ ->
        []
    end
  end

  def presentation_definition(
        ["vp_token" | _response_types],
        presentation_configuration,
        scope,
        request_presentation_definition
      ) do
    case Enum.find(presentation_configuration, fn {identifier, _configuration} ->
           Enum.member?(Scope.split(scope), identifier)
         end) do
      nil ->
        {:ok, nil, request_presentation_definition}

      {identifier, configuration} ->
        {:ok, identifier, configuration[:definition]}
    end
  end

  def presentation_definition(
        _response_types,
        _presentation_configuration,
        _scope,
        request_presentation_definition
      ),
      do: {:ok, nil, request_presentation_definition}

  def validate_presentation(
        vp_token,
        presentation_submission,
        presentation_definition,
        trusted_authorities \\ nil,
        trusted_hosts \\ nil
      ) do
    with :ok <-
           ExJsonSchema.Validator.validate(
             Schema.presentation_submission(),
             presentation_submission,
             error_formatter: BorutaFormatter
           ),
         :ok <-
           validate_descriptor_count(
             presentation_definition["input_descriptors"],
             presentation_submission["descriptor_map"]
           ),
         {:ok, _jwk, vp_claims} <- validate_signature(vp_token) do
      Enum.reduce_while(
        Enum.zip(
          presentation_definition["input_descriptors"],
          presentation_submission["descriptor_map"]
        ),
        {:error, "No credentials presented."},
        fn {descriptor, map}, _acc ->
          credential = get_in(vp_claims, extract_path(map["path_nested"]["path"]))

          case validate_credential(
                 credential,
                 descriptor,
                 extract_format(map),
                 trusted_authorities,
                 trusted_hosts
               ) do
            :ok -> {:cont, :ok}
            {:error, error} -> {:halt, {:error, map["id"] <> " " <> error}}
          end
        end
      )
    else
      {:error, errors} when is_list(errors) ->
        {:error, Enum.join(errors, ", ")}

      error ->
        error
    end
  end

  defp validate_descriptor_count(input_descriptors, descriptor_map)
       when is_list(input_descriptors) and is_list(descriptor_map) do
    case length(input_descriptors) == length(descriptor_map) do
      true -> :ok
      false -> {:error, "Input descriptor count does not match descriptor map count."}
    end
  end

  defp validate_descriptor_count(_input_descriptors, _descriptor_map),
    do: {:error, "Input descriptor count does not match descriptor map count."}

  defp extract_path(raw_path) do
    raw_path
    |> String.split(".")
    |> List.delete("$")
    |> Enum.flat_map(fn part ->
      case Regex.run(~r{\[(\d+)\]}, part) do
        nil ->
          [part]

        [access, i] ->
          [
            String.replace(part, access, ""),
            fn :get, data, next -> next.(Enum.at(data, String.to_integer(i))) end
          ]
      end
    end)
  end

  defp extract_format(%{"path_nested" => %{"format" => format}}), do: format

  def validate_credential(
        credential,
        descriptor,
        format,
        trusted_authorities \\ nil,
        trusted_hosts \\ nil
      )

  def validate_credential(
        credential,
        descriptor,
        "jwt_vc",
        trusted_authorities,
        trusted_hosts
      ) do
    with {:ok, _jwk, claims} <- validate_signature(credential),
         :ok <- validate_expiration(claims),
         :ok <- validate_valid_from(claims),
         :ok <- validate_status_list(claims, trusted_authorities, trusted_hosts) do
      validate_constraints(claims, descriptor)
    end
  end

  def validate_credential(
        credential,
        descriptor,
        "vc+sd-jwt",
        _trusted_authorities,
        _trusted_hosts
      ) do
    with {:ok, jwt, disclosures} <- decode_sd_jwt(credential),
         {:ok, _jwk, claims} <- validate_signature(jwt),
         :ok <- validate_expiration(claims),
         {:ok, disclosed_claims} <- validate_disclosures(claims, disclosures),
         :ok <- validate_disclosure_statuses(claims, disclosures) do
      claims
      |> Map.merge(disclosed_claims)
      |> validate_constraints(descriptor)
    end
  end

  def validate_credential(
        _credential,
        _descriptor,
        format,
        _trusted_authorities,
        _trusted_hosts
      ),
    do: {:error, "format \"#{format}\" is not supported"}

  defp decode_sd_jwt(credential) when is_binary(credential) do
    case String.split(credential, "~") do
      [jwt | disclosures] when jwt != "" ->
        disclosures = Enum.reject(disclosures, &(&1 == ""))

        case disclosures do
          [] -> {:error, "does not contain disclosures."}
          disclosures -> {:ok, jwt, disclosures}
        end

      _ ->
        {:error, "is not a valid SD-JWT credential."}
    end
  end

  defp decode_sd_jwt(_credential), do: {:error, "is not a valid SD-JWT credential."}

  defp validate_disclosures(%{"_sd" => sd_hashes}, disclosures) when is_list(sd_hashes) do
    Enum.reduce_while(disclosures, {:ok, %{}}, fn disclosure, {:ok, claims} ->
      with :ok <- validate_disclosure_hash(disclosure, sd_hashes),
           {:ok, [_salt, name, value]} <- decode_disclosure(disclosure) do
        {:cont, {:ok, put_disclosed_claim(claims, String.split(name, "."), value)}}
      else
        {:error, error} -> {:halt, {:error, error}}
      end
    end)
  end

  defp validate_disclosures(_claims, _disclosures), do: {:error, "_sd claim is missing."}

  defp validate_disclosure_hash(disclosure, sd_hashes) do
    hash = :crypto.hash(:sha256, disclosure) |> Base.url_encode64(padding: false)

    case Enum.member?(sd_hashes, hash) do
      true -> :ok
      false -> {:error, "contains an invalid disclosure."}
    end
  end

  defp decode_disclosure(disclosure) do
    with {:ok, decoded} <- Base.url_decode64(disclosure, padding: false),
         {:ok, [_salt, name, _value] = disclosure_claim} when is_binary(name) <-
           Jason.decode(decoded) do
      {:ok, disclosure_claim}
    else
      _ -> {:error, "contains an invalid disclosure."}
    end
  end

  defp put_disclosed_claim(claims, [key], value), do: Map.put(claims, key, value)

  defp put_disclosed_claim(claims, [key | rest], value) do
    Map.put(claims, key, put_disclosed_claim(Map.get(claims, key, %{}), rest, value))
  end

  defp validate_disclosure_statuses(%{"iss" => iss}, disclosures) do
    Enum.reduce_while(disclosures, :ok, fn disclosure, :ok ->
      with {:ok, [status_token, _name, _value]} <- decode_disclosure(disclosure),
           true <- String.contains?(status_token, "~") do
        case Status.verify_status_token(iss, status_token) do
          :valid -> {:cont, :ok}
          :suspended -> {:halt, {:error, "is suspended."}}
          :revoked -> {:halt, {:error, "is revoked."}}
          :expired -> {:halt, {:error, "is expired."}}
          :invalid -> {:halt, {:error, "has an invalid status."}}
        end
      else
        _ -> {:cont, :ok}
      end
    end)
  end

  defp validate_disclosure_statuses(_claims, _disclosures), do: :ok

  defp validate_expiration(%{"exp" => expiry}) do
    case expiry > :os.system_time(:second) do
      true -> :ok
      false -> {:error, "is expired."}
    end
  end

  defp validate_expiration(_claims), do: {:error, "Credential exp claim is missing."}

  defp validate_valid_from(%{"vc" => %{"validFrom" => valid_from}}) do
    with {:ok, valid_from, _} <- DateTime.from_iso8601(valid_from),
         true <- DateTime.diff(valid_from, DateTime.utc_now(), :second) <= 0 do
      :ok
    else
      _ -> {:error, "is not yet valid."}
    end
  end

  defp validate_valid_from(%{"validFrom" => valid_from}) do
    with {:ok, valid_from, _} <- DateTime.from_iso8601(valid_from),
         true <- DateTime.diff(valid_from, DateTime.utc_now(), :second) <= 0 do
      :ok
    else
      _ -> {:error, "is not yet valid."}
    end
  end

  defp validate_valid_from(_claims), do: {:error, "is invalid"}

  defp validate_status_list(
         %{"vc" => %{"credentialStatus" => status}},
         trusted_authorities,
         trusted_hosts
       ) do
    case HttpClient.get(
           status["statusListCredential"],
           trusted_authorities,
           trusted_hosts
         ) do
      {:ok, %Finch.Response{status: 200, body: status_credential}} ->
        case Joken.peek_claims(status_credential) do
          {:ok, %{"vc" => %{"credentialSubject" => status_list}}} ->
            bit =
              status_list["encodedList"]
              |> :binary.decode_unsigned()
              |> :erlang.integer_to_list(2)
              |> Enum.slice(status["statusListIndex"] |> String.to_integer(), 1)
              |> :string.to_integer()
              |> elem(0)

            case bit do
              1 ->
                :ok

              0 ->
                case status_list["statusPurpose"] do
                  "revocation" ->
                    {:error, "is revoked."}
                end
            end

          _ ->
            {:error, "has an invalid status list credential."}
        end

      _ ->
        {:error, "could not get status list."}
    end
  end

  defp validate_status_list(_claims, _trusted_authorities, _trusted_hosts), do: :ok

  defp validate_constraints(claims, %{
         "id" => id,
         "constraints" => %{"fields" => fields_constraints}
       }) do
    Enum.reduce_while(fields_constraints, :ok, fn constraint, _result ->
      case Enum.reduce_while(constraint["path"], :ok, fn path, _result ->
             value = get_in(claims, extract_path(path))

             case validate_filter(value, constraint["filter"]) do
               :ok -> {:cont, :ok}
               error -> {:halt, error}
             end
           end) do
        :ok -> {:cont, :ok}
        {:error, error} -> {:halt, {:error, "descriptor #{id} #{error}"}}
      end
    end)
  end

  defp validate_constraints(_claims, _descriptor), do: {:error, "descriptor is invalid."}

  defp validate_filter(value, %{"type" => "number", "const" => expected})
       when is_number(value) and value == expected,
       do: :ok

  defp validate_filter(_value, %{"type" => "number", "const" => expected}),
    do: {:error, "does not equal #{inspect(expected)}."}

  defp validate_filter(value, %{"type" => "number"}) when is_number(value), do: :ok

  defp validate_filter(value, %{"type" => "array", "contains" => %{"const" => contains}})
       when is_list(value) do
    case Enum.member?(value, contains) do
      true -> :ok
      false -> {:error, "does not contains \"#{contains}\"."}
    end
  end

  defp validate_filter(value, %{"type" => "string", "pattern" => pattern})
       when is_binary(value) do
    case Regex.match?(~r/#{pattern}/, value) do
      true -> :ok
      false -> {:error, "does not contain pattern \"#{pattern}\"."}
    end
  end

  defp validate_filter(value, %{"type" => "array", "contains" => %{"const" => contains}})
       when is_list(value) do
    case Enum.member?(value, contains) do
      true -> :ok
      false -> {:error, "does not contains #{contains}."}
    end
  end

  defp validate_filter(_value, nil), do: :ok

  defp validate_filter(_value, _filter), do: {:error, "has an invalid or unknown filter."}

  @spec validate_signature(jwt :: String.t()) ::
          {:ok, jwk :: map(), claims :: map()} | {:error, reason :: String.t()}
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

  @spec verify_jwt({:did, String.t()} | {:jwk, String.t()}, alg :: String.t(), jwt :: String.t()) ::
          {:ok, jwk :: map(), claims :: map()} | {:error, String.t()}
  def verify_jwt({:did, did}, alg, jwt) do
    with {:ok, did_document} <- Did.resolve(did),
         %{"verificationMethod" => methods} <- did_document do
      Enum.reduce_while(
        methods,
        {:error, "no did verification method found with did #{did}."},
        fn %{"publicKeyJwk" => jwk}, {:error, errors} ->
          signer =
            Joken.Signer.create(alg, %{"pem" => JOSE.JWK.from_map(jwk) |> JOSE.JWK.to_pem()})

          case Client.Token.verify(jwt, signer) do
            {:ok, claims} ->
              {:halt, {:ok, jwk, claims}}

            {:error, error} ->
              {:cont, {:error, errors <> ", #{inspect(error)} with key #{inspect(jwk)}"}}
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

  def verify_jwt({:jwk, jwk}, alg, jwt) do
    signer = Joken.Signer.create(alg, %{"pem" => jwk |> JOSE.JWK.from_map() |> JOSE.JWK.to_pem()})

    case Token.verify(jwt, signer) do
      {:ok, claims} ->
        {:ok, jwk, claims}

      _ ->
        {:error, "Bad proof signature"}
    end
  end

  def verify_jwt(error, _alg, _jwt), do: error

  defp extract_key(%{"jwk" => jwk}), do: {:jwk, jwk}
  defp extract_key(%{"kid" => did}), do: {:did, did}
  defp extract_key(_headers), do: {:error, "No proof key material found in JWT headers"}
end
