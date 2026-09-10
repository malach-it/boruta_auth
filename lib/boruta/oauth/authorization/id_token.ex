defmodule Boruta.Oauth.Authorization.IdToken do
  @moduledoc """
  Validates the self-issued ID token used by the code-chain grant.
  """

  alias Boruta.Oauth.Error

  defmodule Token do
    @moduledoc false

    use Joken.Config

    def token_config, do: %{}
  end

  @asymmetric_algorithms ~w(ES256 ES384 ES512 RS256 RS384 RS512 EdDSA)

  @spec authorize(id_token :: String.t()) :: {:ok, claims :: map()} | {:error, Error.t()}
  def authorize(id_token) when is_binary(id_token) do
    with {:ok, %{"alg" => alg, "jwk" => jwk}} <- Joken.peek_header(id_token),
         true <- alg in @asymmetric_algorithms,
         {:ok, signer} <- signer(alg, jwk),
         {:ok, claims} <- Token.verify(id_token, signer),
         :ok <- validate_claims(claims) do
      {:ok, claims}
    else
      {:ok, %{"alg" => alg, "jwk" => _jwk}} when alg not in @asymmetric_algorithms ->
        invalid_id_token("id_token signing algorithm is invalid.")

      {:ok, _headers} ->
        invalid_id_token("id_token header must include alg and jwk.")

      {:error, :signature_error} ->
        invalid_id_token("id_token signature is invalid.")

      {:error, :invalid_key} ->
        invalid_id_token("id_token jwk is invalid.")

      {:error, %Error{} = error} ->
        {:error, error}

      _ ->
        invalid_id_token("id_token must be a jwt.")
    end
  end

  def authorize(_id_token), do: invalid_id_token("id_token must be a jwt.")

  defp signer(alg, jwk) when is_map(jwk) do
    {:ok,
     Joken.Signer.create(alg, %{
       "pem" => JOSE.JWK.from_map(jwk) |> JOSE.JWK.to_pem()
     })}
  rescue
    _error -> {:error, :invalid_key}
  end

  defp signer(_alg, _jwk), do: {:error, :invalid_key}

  defp validate_claims(%{"sub" => sub, "iat" => iat, "exp" => exp})
       when is_binary(sub) and sub != "" and is_integer(iat) and is_integer(exp) do
    now = :os.system_time(:second)

    cond do
      exp <= iat -> invalid_id_token("id_token exp must be after iat.")
      iat > now -> invalid_id_token("id_token iat must not be in the future.")
      exp <= now -> invalid_id_token("id_token is expired.")
      true -> :ok
    end
  end

  defp validate_claims(%{"iat" => iat, "exp" => exp})
       when is_integer(iat) and is_integer(exp) and exp <= iat do
    invalid_id_token("id_token exp must be after iat.")
  end

  defp validate_claims(%{"iat" => _iat, "exp" => _exp}) do
    invalid_id_token("id_token sub is required.")
  end

  defp validate_claims(%{"iat" => _iat}) do
    invalid_id_token("id_token exp is required.")
  end

  defp validate_claims(%{"exp" => _exp}) do
    invalid_id_token("id_token iat is required.")
  end

  defp validate_claims(_claims) do
    invalid_id_token("id_token iat and exp are required.")
  end

  defp invalid_id_token(error_description) do
    {:error,
     %Error{
       status: :bad_request,
       error: :invalid_grant,
       error_description: error_description
     }}
  end
end
