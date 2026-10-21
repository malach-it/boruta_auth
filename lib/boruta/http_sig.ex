defmodule Boruta.HttpSig do
  @moduledoc false

  defstruct scheme: nil,
            params: %{}

  @type parameter_value :: String.t() | binary() | boolean()
  @type key_entry :: %{scheme: String.t(), params: %{String.t() => parameter_value()}}
  @type t :: %__MODULE__{
          scheme: String.t(),
          params: map()
        }

  @sig_regex ~r/([^=]+)=(hwk|jkt-jwt|jwks_uri|jwks|jwt|self-jwt|x509|cached);(([^=]+)=\"?([^;|\"]+)\"?;?)+/

  @spec validate(request :: map()) :: :ok | {:error, String.t()}
  def validate(%{req_headers: req_headers} = request) do
    with {"signature-key", sig_header} <- List.keyfind(req_headers, "signature-key", 0),
         true <- Enum.count(req_headers, fn {key, _value} -> key == "signature-key" end) == 1,
         sigs <- String.split(sig_header, ","),
         http_sigs <- parse_http_sigs(sigs) do
      Enum.reduce_while(
        http_sigs,
        {:error, "No HTTP signature are present in request."},
      fn
        {_name, %__MODULE__{scheme: "jwt"} = http_sig}, _acc ->
          with {:ok, _claims} <- verify_jwt(http_sig.params["jwt"]),
               :ok <- verify_issuer(http_sig.params["jwt"], request) do
            {:cont, :ok}
          else
            {:error, error} ->
              {:halt, {:error, error}}
          end
        {_name, _http_sig}, _acc ->
          {:halt, {:error, "Agent token signature scheme not supported."}}
        end
      )
    else
      nil ->
        {:error, "Signature-Key header is required."}

      false ->
        {:error, "More than one Signature-Key header present in the request."}

      error ->
        error
    end
  end

  defp parse_http_sigs(sigs) do
    Enum.map(sigs, fn sig ->
      case Regex.run(@sig_regex, sig) do
        [_all, name, scheme, _parameters | params] ->
          {name,
           %__MODULE__{
             scheme: scheme,
             params: Enum.chunk_every(params, 2) |> Enum.map(&List.to_tuple/1) |> Enum.into(%{})
           }}

        _ ->
          nil
      end
    end)
    |> Enum.reject(&is_nil/1)
    |> Enum.into(%{})
  end

  defp verify_jwt(jwt) do
    case Joken.peek_header(jwt) do
      {:ok, %{"typ" => "aa-agent+jwt", "alg" => alg}} ->
        case Joken.peek_claims(jwt) do
          {:ok,
           %{
             "cnf" => %{
               "jwk" => jwk
             }
           }} ->
            signer =
              Joken.Signer.create(alg, %{"pem" => JOSE.JWK.from_map(jwk) |> JOSE.JWK.to_pem()})

            case Joken.verify(jwt, signer) do
              {:ok, claims} -> {:ok, claims}
              {:error, _error} -> {:error, "Could not verify Agent token."}
            end

          _ ->
            {:error, "Agent token must contain a cnf jwk key."}
        end

      _ ->
        {:error, "Agent token header is invalid."}
    end
  end

  defp verify_issuer(jwt, %{scheme: scheme, host: host}) do
    issuer_url = URI.to_string(%URI{scheme: scheme, host: host})

    with {:ok, %{"iss" => ^issuer_url}} <- Joken.peek_claims(jwt) do
      :ok
    else
      _ ->
        {:error, "Request host do not match agent token issuer."}
    end
  end

  defp verify_issuer(_jwt, _request) do
    {:error, "Request host do not match agent token issuer."}
  end
end
