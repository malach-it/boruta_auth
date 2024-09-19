defmodule Boruta.Openid.VerifiablePresentations do
  # TODO add typespec definitions for public functions
  @moduledoc false

  defmodule Token do
    @moduledoc false

    use Joken.Config

    def token_config, do: %{}
  end

  alias Boruta.Did
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Scope
  alias Boruta.Openid.Json.Schema
  alias ExJsonSchema.Validator.Error.BorutaFormatter

  # TODO perform client metadata checks
  def check_client_metadata(_client_metadata), do: :ok

  def response_types("code", _scope, _presentation_configuration), do: ["id_token"]

  def response_types("id_token", _scope, _presentation_configuration), do: ["id_token"]

  def response_types("vp_token", scope, presentation_configuration) do
    case Enum.any?(Map.keys(presentation_configuration), fn presentation_identifier ->
           Enum.member?(Scope.split(scope), presentation_identifier)
         end) do
      true -> ["vp_token"]
      false -> ["id_token"]
    end
  end

  def presentation_definition(presentation_configuration, scope) do
    case Enum.find(presentation_configuration, fn {identifier, _configuration} ->
           Enum.member?(Scope.split(scope), identifier)
         end) do
      nil ->
        nil

      {_identifier, configuration} ->
        configuration[:definition]
    end
  end

  def validate_presentation(vp_token, presentation_submission, presentation_definition) do
    with :ok <-
           ExJsonSchema.Validator.validate(
             Schema.presentation_submission(),
             presentation_submission,
             error_formatter: BorutaFormatter
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

          case validate_credential(credential, descriptor, extract_format(map)) do
            {:ok, sub, current_claims} -> {:cont, {:ok, sub, Map.merge(claims, current_claims)}}
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

  def validate_credential(credential, descriptor, "jwt_vc") do
    with {:ok, _jwk, claims} <- validate_signature(credential),
         :ok <- validate_expiration(claims),
         :ok <- validate_valid_from(claims),
         :ok <- validate_status_list(claims),
         {:ok, filtered_claims} <- validate_constraints(claims, descriptor) do
      {:ok, claims["sub"], filtered_claims}
    end
  end

  def validate_credential(_credential, _descriptor, format),
    do: {:error, "format \"#{format}\" is not supported"}

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

  defp validate_status_list(%{"vc" => %{"credentialStatus" => status}}) do
    case Finch.build(:get, status["statusListCredential"]) |> Finch.request(OpenIDHttpClient) do
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

  defp validate_status_list(_claims), do: :ok

  defp validate_constraints(claims, %{
         "id" => id,
         "constraints" => %{"fields" => fields_constraints}
       }) do
    Enum.reduce_while(fields_constraints, :ok, fn constraint, _result ->
      case Enum.reduce_while(constraint["path"], {:ok, %{}}, fn path,
                                                                {:ok, presentation_claims} ->
             path = extract_path(path)
             value = get_in(claims, path)

             case validate_filter(value, constraint["filter"]) do
               :ok -> {:cont, {:ok, Map.put(presentation_claims, Enum.join(path, "."), value)}}
               error -> {:halt, error}
             end
           end) do
        {:ok, claims} -> {:cont, {:ok, claims}}
        {:error, error} -> {:halt, {:error, "descriptor #{id} #{error}"}}
      end
    end)
  end

  defp validate_constraints(_claims, _descriptor), do: {:error, "descriptor is invalid."}

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

  defp extract_key(%{"kid" => did}), do: {:did, did}
  defp extract_key(%{"jwk" => jwk}), do: {:jwk, jwk}
  defp extract_key(_headers), do: {:error, "No proof key material found in JWT headers"}
end
