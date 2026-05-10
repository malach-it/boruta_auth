defmodule Boruta.Oauth.Authorization.IdToken do
  @moduledoc """
  Check against given params and return the corresponding id token claims.
  """

  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Error

  @spec authorize(id_token :: String.t()) :: {:ok, claims :: map()} | {:error, Error.t()}
  def authorize(id_token) do
    with {:ok, %{"alg" => alg, "jwk" => jwk}} <- Joken.peek_header(id_token),
         signer <-
           Joken.Signer.create(alg, %{"pem" => JOSE.JWK.from_map(jwk) |> JOSE.JWK.to_pem()}),
         {:ok, claims} <- Client.Token.verify(id_token, signer),
         :ok <- validate_claims(claims) do
      {:ok, claims}
    else
      {:ok, _headers} ->
        invalid_id_token("id_token header must include alg and jwk.")

      {:error, %Joken.Error{reason: :signature_error}} ->
        invalid_id_token("id_token signature is invalid.")

      {:error, %Joken.Error{reason: :token_expired}} ->
        invalid_id_token("id_token is expired.")

      {:error, %Joken.Error{}} ->
        invalid_id_token("id_token claims are invalid.")

      _ ->
        invalid_id_token("id_token must be a jwt.")
    end
  end

  defp validate_claims(%{"sub" => sub, "iat" => iat, "exp" => exp})
       when is_binary(sub) and is_integer(iat) and is_integer(exp) and exp > iat do
    now = :os.system_time(:seconds)

    case iat <= now do
      true -> :ok
      false -> invalid_id_token("id_token iat must not be in the future.")
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
