defmodule Boruta.Openid.SiopV2Response do
  @moduledoc """
  Response in case of delivrance of Siop V2 flow
  """

  import Boruta.Config, only: [issuer: 0]

  alias Boruta.Oauth.Client

  @enforce_keys [
    :client_id,
    :code,
    :response_type,
    :scope,
    :redirect_uri,
    :issuer,
    :client,
    :response_mode,
    :nonce
  ]

  defstruct client_id: nil,
            code: nil,
            response_type: nil,
            scope: nil,
            redirect_uri: nil,
            issuer: nil,
            client: nil,
            response_mode: nil,
            nonce: nil

  @type t :: %__MODULE__{
          client_id: String.t(),
          code: Boruta.Oauth.Token.t(),
          response_type: String.t(),
          scope: String.t(),
          redirect_uri: String.t(),
          issuer: String.t(),
          client: Boruta.Oauth.Client.t(),
          response_mode: String.t(),
          nonce: String.t()
        }

  def from_tokens(%{siopv2_code: code}, request) do
    %__MODULE__{
      client_id: request.client_id,
      code: code,
      response_type: request.response_type,
      scope: code.scope,
      redirect_uri: code.redirect_uri,
      issuer: Boruta.Config.issuer(),
      client: code.client,
      response_mode: "direct_post",
      nonce: code.nonce
    }
  end

  @spec redirect_to_deeplink(
          response :: t(),
          redirect_uri_url_fn :: (code :: String.t() -> url :: String.t())
        ) :: deeplink :: String.t() | {:error, reason :: String.t()}
  def redirect_to_deeplink(%__MODULE__{} = response, redirect_uri_url_fn) do
    redirect_uri = redirect_uri_url_fn.(response.code.id)
    claims = %{
      iss: issuer(),
      aud: response.client_id,
      exp: :os.system_time(:seconds) + response.client.authorization_code_ttl,
      response_type: response.response_type,
      response_mode: response.response_mode,
      client_id: issuer(),
      redirect_uri: redirect_uri,
      scope: response.scope,
      nonce: response.nonce
    }

    with "" <> request <- Client.Crypto.id_token_sign(claims, response.client) do
      query =
        %{
          client_id: response.client_id,
          response_type: response.response_type,
          response_mode: response.response_mode,
          scope: response.scope,
          redirect_uri: redirect_uri,
          request: request
        }
        |> URI.encode_query()

      uri = URI.parse(response.redirect_uri)
      uri = %{uri | host: uri.host || "", query: query}

      URI.to_string(uri)
    end
  end
end
