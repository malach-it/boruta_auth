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
  def validate(:token, %{"grant_type" => grant_type} = params)
      when grant_type in ["password", "client_credentials", "agent_credentials", "agent_code", "authorization_code", "refresh_token"] do
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

  def validate(:token, %{"grant_type" => "urn:ietf:params:oauth:grant-type:pre-authorized_code"} = params) do
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

  def validate(:token, %{"grant_type" => _} = params) do
    case ExJsonSchema.Validator.validate(
           Schema.grant_type(),
           params,
           error_formatter: BorutaFormatter
         ) do
      {:error, errors} ->
        {:error, "Request body validation failed. " <> Enum.join(errors, " ")}
    end
  end

  def validate(:authorize, %{"response_type" => response_types} = params)
      when response_types in [
             "token",
             "vp_token",
             "id_token",
             "id_token token",
             "id_token urn:ietf:params:oauth:response-type:pre-authorized_code",
             "id_token vp_token",
             "code",
             "code id_token",
             "code token",
             "code id_token token"
           ] do
    case validate_multiple_response_types(params) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        {:error, "Query params validation failed. " <> Enum.join(errors, " ")}
    end
  end

  def validate(:authorize, %{"response_type" => "urn:ietf:params:oauth:response-type:pre-authorized_code"} = params) do
    case ExJsonSchema.Validator.validate(
           Schema.preauthorized_code(),
           params,
           error_formatter: BorutaFormatter
         ) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        {:error, "Query params validation failed. " <> Enum.join(errors, " ")}
    end
  end

  def validate(:authorize, %{"response_type" => _}) do
    {:error,
     "Invalid response_type param."}
  end

  def validate(:introspect, params) do
    case ExJsonSchema.Validator.validate(Schema.introspect(), params,
           error_formatter: BorutaFormatter
         ) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        {:error, "Request validation failed. " <> Enum.join(errors, " ")}
    end
  end

  def validate(:revoke, params) do
    case ExJsonSchema.Validator.validate(Schema.revoke(), params, error_formatter: BorutaFormatter) do
      :ok ->
        {:ok, params}

      {:error, errors} ->
        {:error, "Request validation failed. " <> Enum.join(errors, " ")}
    end
  end

  def validate(:token, _params) do
    {:error, "Request is not a valid OAuth request. Need a grant_type param."}
  end

  def validate(:authorize, _params) do
    {:error, "Request is not a valid OAuth request. Need a response_type param."}
  end

  defp validate_multiple_response_types(%{"response_type" => response_types} = params) do
    response_types
    |> String.split(" ")
    # TODO validate custom preauthorized code requests
    |> Enum.reject(fn response_type -> response_type == "urn:ietf:params:oauth:response-type:pre-authorized_code" end)
    |> Enum.reduce_while(:ok, fn response_type, _acc ->
      case ExJsonSchema.Validator.validate(
             apply(Schema, String.to_atom(response_type), []),
             params,
             error_formatter: BorutaFormatter
           ) do
        :ok -> {:cont, :ok}
        {:error, errors} -> {:halt, {:error, errors}}
      end
    end)
  end
end
