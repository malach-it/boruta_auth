defmodule Boruta.VerifiablePresentations do
  @moduledoc false

  defmodule Token do
    @moduledoc false

    use Joken.Config

    def token_config, do: %{}
  end

  alias Boruta.Did
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Scope

  # TODO perform client metadata checks
  def check_client_metadata(_client_metadata), do: :ok

  def response_types(scope, presentation_configuration) do
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

  @spec validate_signature(jwt :: String.t()) ::
          {:ok, jwk ::map(), claims :: map()} | {:error, reason :: String.t()}
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
    case Did.resolve(did) do
      {:ok, did_document} ->
        %{"didDocument" => %{"verificationMethod" => [%{"publicKeyJwk" => jwk}]}} =
          did_document

        signer = Joken.Signer.create(alg, %{"pem" => JOSE.JWK.from_map(jwk) |> JOSE.JWK.to_pem()})

        case Client.Token.verify(jwt, signer) do
          {:ok, claims} -> {:ok, jwk, claims}
          {:error, error} -> {:error, inspect(error)}
        end

      {:error, error} ->
        {:error, error}
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

  defp extract_key(%{"kid" => did}), do: {:did, did}
  defp extract_key(%{"jwk" => jwk}), do: {:jwk, jwk}
  defp extract_key(_headers), do: {:error, "No proof key material found in JWT headers"}
end
