defmodule Boruta.IssuerCoordinator.Signatures do
  @moduledoc false

  @behaviour Boruta.Oauth.Signatures
  @behaviour Boruta.Openid.Signatures

  import Boruta.Config, only: [issuer_coordinator_sign_url: 0]

  @impl Boruta.Oauth.Signatures
  defdelegate hash_alg(client), to: Boruta.Internal.Signatures

  @impl Boruta.Oauth.Signatures
  defdelegate hash_binary_size(client), to: Boruta.Internal.Signatures

  @impl Boruta.Oauth.Signatures
  defdelegate hash(string, client), to: Boruta.Internal.Signatures

  @impl Boruta.Oauth.Signatures
  defdelegate id_token_sign(payload, client), to: Boruta.Internal.Signatures

  @impl Boruta.Oauth.Signatures
  defdelegate userinfo_sign(payload, client), to: Boruta.Internal.Signatures

  @impl Boruta.Oauth.Signatures
  defdelegate userinfo_signature_type(client), to: Boruta.Internal.Signatures

  @impl Boruta.Openid.Signatures
  def verifiable_credential_sign(payload, _client, _format) do
    case Finch.build(
           :post,
           issuer_coordinator_sign_url(),
           [
             {"Content-Type", "application/json"}
           ],
           Jason.encode!(payload)
         )
         |> Finch.request(OpenIDHttpClient) do
      {:ok, %Finch.Response{status: 200, body: credential}} ->
        {:ok, credential}

      _ ->
        {:error, "Could not sign with universal key."}
    end
  end
end
