defmodule Boruta.Oauth.IdToken do
  @moduledoc """
  OpenID Connect id token schema and utilities
  """

  import Boruta.Config, only: [resource_owners: 0, issuer: 0]

  alias Boruta.Did
  alias Boruta.Oauth
  alias Boruta.Oauth.Client

  @type claim_definition :: map()

  @type claims ::
          %{
            String.t() => term() | claims()
          }
          | %{
              String.t() => claim_definition() | claims()
            }

  @type tokens :: %{
          optional(:code) => %Oauth.Token{
            sub: String.t(),
            client: Oauth.Client.t(),
            inserted_at: DateTime.t(),
            scope: String.t()
          },
          optional(:token) => %Oauth.Token{
            sub: String.t(),
            client: Oauth.Client.t(),
            inserted_at: DateTime.t(),
            scope: String.t()
          },
          optional(:base_token) => %Oauth.Token{
            sub: String.t(),
            client: Oauth.Client.t(),
            inserted_at: DateTime.t(),
            scope: String.t()
          }
        }

  @spec generate(tokens :: tokens(), nonce :: String.t()) :: id_token :: Oauth.Token.t()
  def generate(tokens, nonce) do
    {base_token, payload} = payload(tokens, nonce, %{})

    value = Client.Crypto.id_token_sign(payload, base_token.client)
    %{base_token | type: "id_token", value: value}
  end

  defp payload(%{code: code} = tokens, nonce, acc) do
    tokens
    |> Map.put(:base_token, code)
    |> Map.delete(:code)
    |> payload(nonce, Map.put(acc, "c_hash", Client.Crypto.hash(code.value, code.client)))
  end

  defp payload(%{token: token} = tokens, nonce, acc) do
    tokens
    |> Map.put(:base_token, token)
    |> Map.delete(:token)
    |> payload(nonce, Map.put(acc, "at_hash", Client.Crypto.hash(token.value, token.client)))
  end

  defp payload(%{base_token: base_token}, nonce, acc) do
    {base_token, Map.merge(acc, payload(base_token, nonce))}
  end

  defp payload(
         %Oauth.Token{
           sub: sub,
           client: client,
           inserted_at: inserted_at,
           scope: scope,
           resource_owner: resource_owner
         },
         nonce
       ) do
    iat = DateTime.to_unix(inserted_at)

    auth_time =
      case resource_owner.last_login_at do
        nil -> :os.system_time(:seconds)
        last_login_at -> DateTime.to_unix(last_login_at)
      end

    resource_owners().claims(resource_owner, scope)
    |> Map.merge(format_claims(resource_owner.extra_claims))
    |> Map.put("sub", sub)
    |> Map.put("iss", Did.controller(client.did) || issuer())
    |> Map.put("aud", client.id)
    |> Map.put("iat", iat)
    |> Map.put("auth_time", auth_time)
    |> Map.put("exp", iat + client.id_token_ttl)
    |> Map.put("nonce", nonce)
  end

  @doc """
  Format claims according to either a claim value or a claim definition.

  Claim definitions contain the "display" and "value" reserved words helping the formatting.
  """
  @spec format_claims(claims :: claims()) :: claims()
  def format_claims(claims) do
    Enum.map(claims, &format_claim/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.into(%{})
  end

  defp format_claim({_key, %{"display" => false}}), do: nil

  defp format_claim({key, %{"display" => []} = value}), do: {key, value["value"]}

  defp format_claim({key, %{"display" => attributes} = value}) when is_list(attributes),
    do: {key, Map.take(value, ["value"] ++ attributes)}

  defp format_claim({key, %{"value" => value}}), do: {key, value}

  defp format_claim(claim), do: claim
end
