defmodule Boruta.Dpop do
  @moduledoc """
  Implementation of [OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://datatracker.ietf.org/doc/html/rfc9449) RFC from the IETF
  """

  defmodule Token do
    @moduledoc false

    use Joken.Config, default_signer: :pem_rs512
  end

  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Error

  @type t :: %{
          dpop: String.t(),
          request: map()
        }

  @spec validate(dpop :: t(), client :: Client.t()) :: :ok | {:error, reason :: String.t()}
  def validate(_dpop, %Client{enforce_dpop: false}), do: :ok

  def validate(%{request: request, dpop: dpop}, %Client{enforce_dpop: true}) do
    with {:ok, %{"typ" => "dpop+jwt", "alg" => alg, "jwk" => jwk}} <- Joken.peek_header(dpop),
         [_alg_type] <- Regex.run(~r/^RS|ES/, alg) do
      signer = Joken.Signer.create(alg, %{"pem" => JOSE.JWK.from_map(jwk) |> JOSE.JWK.to_pem()})

      case Token.verify(dpop, signer) do
        {:ok, claims} ->
          case validate_request(request, claims) do
            :ok ->
              :ok

            {:error, reason} ->
              {:error,
               %Error{
                 status: :bad_request,
                 error: :bad_request,
                 error_description: reason
               }}
          end

        {:error, error} ->
          {:error,
           %Error{
             status: :bad_request,
             error: :bad_request,
             error_description: "Invalid DPoP signature: #{inspect(error)}"
           }}
      end
    else
      nil ->
        {:error,
         %Error{
           status: :bad_request,
           error: :bad_request,
           error_description: "DPoP must be signed with an asymetric algorithm."
         }}

      {:ok, _payload} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :bad_request,
           error_description: "Missing required JWT headers in DPoP."
         }}

      {:error, error} ->
        {:error,
         %Error{
           status: :bad_request,
           error: :bad_request,
           error_description: "DPoP header malformed: #{inspect(error)}"
         }}
    end
  rescue
    _ ->
      {:error,
       %Error{
         status: :bad_request,
         error: :bad_request,
         error_description: "Could not validate DPoP header."
       }}
  end

  defp validate_request(%{method: method, host: host, request_path: request_path}, %{"htm" => htm, "htu" => htu}) do
    case method == htm do
      true ->
        with true <- Regex.match?(~r/#{host}/, htu),
             true <- Regex.match?(~r/#{request_path}/, htu) do
            :ok
        else
          false ->
            {:error, "DPoP allowed URL does not match request."}
        end

      false ->
        {:error, "DPoP allowed method does not match request."}
    end
  end

  defp validate_request(_request, _claims),
    do: {:error, "`htm` or `htu` claims missing in DPoP header JWT."}
end
