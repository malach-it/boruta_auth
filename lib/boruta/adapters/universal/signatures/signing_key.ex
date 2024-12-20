defmodule Boruta.Universal.Signatures.SigningKey do
  @moduledoc false

  @enforce_keys [:type]
  defstruct [:type, :kid, :public_key, :private_key, :secret, :trust_chain]

  import Boruta.Config,
    only: [
      universal_did_auth: 0,
      universal_keys_base_url: 0,
      universal_sign_base_url: 0
    ]

  @type t :: %__MODULE__{
          type: :external | :internal,
          public_key: String.t() | nil,
          private_key: String.t() | nil,
          kid: String.t() | nil,
          secret: String.t() | nil,
          trust_chain: list(String.t()) | nil
        }

  def encode_and_sign_with_key(%__MODULE__{kid: kid, private_key: key_id}, payload) do
    header =
      %{
        "typ" => "JWT",
        "alg" => "EdDSA",
        "kid" => kid
      }
      |> Jason.encode!()
      |> Base.url_encode64(padding: false)

    payload =
      Jason.encode!(payload)
      |> Base.url_encode64(padding: false)

    case Finch.build(
           :post,
           universal_sign_base_url() <> "?id=#{key_id}&algorithm=EdDSA",
           [
             {"Authorization", "Bearer #{universal_did_auth()[:token]}"},
             {"Content-Type", "application/octet-stream"}
           ],
           "#{header}.#{payload}"
         )
         |> Finch.request(OpenIDHttpClient) do
      {:ok, %Finch.Response{status: 200, body: signature}} ->
        {:ok, "#{header}.#{payload}.#{Base.url_encode64(signature, padding: false)}"}

      _ ->
        {:error, "Could not sign with universal key."}
    end
  end

  def get_key_by_did(did) do
    with {:ok, %Finch.Response{status: 200, body: body}} <-
           Finch.build(
             :get,
             universal_keys_base_url(),
             [
               {"Authorization", "Bearer #{universal_did_auth()[:token]}"},
               {"Content-Type", "application/json"}
             ]
           )
           |> Finch.request(OpenIDHttpClient),
         {:ok, keys} <- Jason.decode(body) do
      case Enum.filter(keys, fn %{"controller" => controller} -> controller == did end) do
        [key] ->
          {:ok, key}

        _ ->
          {:error, "Could not fetch universal key."}
      end
    else
      _ ->
        {:error, "Could not fetch universal key."}
    end
  end
end
