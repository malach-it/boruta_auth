defmodule Boruta.Oauth.Validator do
  @moduledoc """
  Utility to validate the request according to the given parameters
  """

  # TODO find a way to difference query from body params
  alias Boruta.Oauth.Json.Schema
  alias ExJsonSchema.Validator.Error.BorutaFormatter

  @doc """
  Validates given OAuth parameters.
  ## Examples
      iex> validate(:token, %{
        "grant_type" => "client_credentials",
        "client_id" => "client_id",
        "client_secret" => "client_secret"
      })
      {:ok, %{
        "grant_type" => "client_credentials",
        "client_id" => "client_id",
        "client_secret" => "client_secret"
      }}

      iex> validate(:authorize, %{})
      {:error, "Request is not a valid OAuth request. Need a response_type param."}
  """
  @spec validate(action :: :token | :authorize | :introspect | :revoke, params :: map()) ::
          {:ok, params :: map()} | {:error, message :: String.t()}
  def validate(action, params) do
    # Postgres rejects NUL in text, so a param carrying one would raise on
    # whichever query it reaches.
    if nul_byte?(params) do
      {:error, "Request params must not contain NUL bytes."}
    else
      validate_schema(action, params)
    end
  end

  defp validate_schema(:token, %{"grant_type" => grant_type} = params)
       when grant_type in [
              "password",
              "client_credentials",
              "agent_credentials",
              "code_chain",
              "agent_code",
              "authorization_code",
              "refresh_token"
            ] do
    case ExJsonSchema.Validator.validate(
           apply(Schema, String.to_atom(grant_type), []),
           params,
           error_formatter: BorutaFormatter
         ) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        {:error, "Request body validation failed. " <> Enum.join(errors, " ")}
    end
  end

  defp validate_schema(
         :token,
         %{"grant_type" => "urn:ietf:params:oauth:grant-type:pre-authorized_code"} = params
       ) do
    case ExJsonSchema.Validator.validate(
           Schema.preauthorization_code(),
           params,
           error_formatter: BorutaFormatter
         ) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        {:error, "Request body validation failed. " <> Enum.join(errors, " ")}
    end
  end

  defp validate_schema(:token, %{"grant_type" => _} = params) do
    case ExJsonSchema.Validator.validate(
           Schema.grant_type(),
           params,
           error_formatter: BorutaFormatter
         ) do
      {:error, errors} ->
        {:error, "Request body validation failed. " <> Enum.join(errors, " ")}
    end
  end

  defp validate_schema(:authorize, %{"response_type" => "token"} = params) do
    case validate_multiple_response_types(params) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        authorize_error(errors)
    end
  end

  defp validate_schema(:authorize, %{"response_type" => "vp_token" <> _rest} = params) do
    case validate_multiple_response_types(params) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        authorize_error(errors)
    end
  end

  defp validate_schema(:authorize, %{"response_type" => "id_token" <> _rest} = params) do
    case validate_multiple_response_types(params) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        authorize_error(errors)
    end
  end

  defp validate_schema(:authorize, %{"response_type" => "code" <> _rest} = params) do
    case validate_multiple_response_types(params) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        authorize_error(errors)
    end
  end

  defp validate_schema(
         :authorize,
         %{"response_type" => "urn:ietf:params:oauth:response-type:pre-authorized_code"} = params
       ) do
    case ExJsonSchema.Validator.validate(
           Schema.preauthorized_code(),
           params,
           error_formatter: BorutaFormatter
         ) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        authorize_error(errors)
    end
  end

  defp validate_schema(:authorize, %{"response_type" => _response_types} = params) do
    case validate_multiple_response_types(params) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        authorize_error(errors)
    end
  end

  defp validate_schema(:introspect, params) do
    case ExJsonSchema.Validator.validate(Schema.introspect(), params,
           error_formatter: BorutaFormatter
         ) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        {:error, "Request validation failed. " <> Enum.join(errors, " ")}
    end
  end

  defp validate_schema(:revoke, params) do
    case ExJsonSchema.Validator.validate(Schema.revoke(), params,
           error_formatter: BorutaFormatter
         ) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        {:error, "Request validation failed. " <> Enum.join(errors, " ")}
    end
  end

  defp validate_schema(:token, _params) do
    {:error, "Request is not a valid OAuth request. Need a grant_type param."}
  end

  defp validate_schema(:authorize, _params) do
    {:error, "Request is not a valid OAuth request. Need a response_type param."}
  end

  defp authorize_error(["Invalid response_type param."]) do
    {:error, "Invalid response_type param."}
  end

  defp authorize_error(errors) do
    {:error, "Query params validation failed. " <> Enum.join(errors, " ")}
  end

  defp validate_multiple_response_types(%{"response_type" => response_types} = params) do
    response_type_schemas = %{
      "code" => :code,
      "id_token" => :id_token,
      "token" => :token,
      "vp_token" => :vp_token
    }

    response_types
    |> String.split(" ")
    # TODO validate custom preauthorized code requests
    |> Enum.reject(fn response_type ->
      response_type == "urn:ietf:params:oauth:response-type:pre-authorized_code"
    end)
    |> Enum.reduce_while(:ok, fn response_type, _acc ->
      case Map.fetch(response_type_schemas, response_type) do
        {:ok, schema_name} ->
          case ExJsonSchema.Validator.validate(
                 apply(Schema, schema_name, []),
                 params,
                 error_formatter: BorutaFormatter
               ) do
            :ok -> {:cont, :ok}
            {:error, errors} -> {:halt, {:error, errors}}
          end

        :error ->
          {:halt, {:error, ["Invalid response_type param."]}}
      end
    end)
  end

  defp nul_byte?(value) when is_binary(value), do: String.contains?(value, <<0>>)
  defp nul_byte?(values) when is_list(values), do: Enum.any?(values, &nul_byte?/1)

  defp nul_byte?(params) when is_map(params) and not is_struct(params),
    do: Enum.any?(params, fn {key, value} -> nul_byte?(key) or nul_byte?(value) end)

  defp nul_byte?(_value), do: false
end
