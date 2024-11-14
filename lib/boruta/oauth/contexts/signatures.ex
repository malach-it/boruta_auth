defmodule Boruta.Oauth.Signatures do
  @moduledoc """
  TODO Utilities to provide signature abilities to OAuth clients
  """

  @callback signature_algorithms() :: list(atom())
  @callback hash_alg(Boruta.Oauth.Client.t()) :: hash_alg :: atom()
  @callback hash_binary_size(Boruta.Oauth.Client.t()) :: binary_size :: integer()
  @callback hash(string :: String.t(), client :: Boruta.Oauth.Client.t()) :: hash :: String.t()
  @callback id_token_sign(payload :: map(), client :: Boruta.Oauth.Client.t()) ::
              jwt :: String.t() | {:error, reason :: String.t()}
  @callback verify_id_token_signature(id_token :: String.t(), jwk :: JOSE.JWK.t()) ::
              :ok | {:error, reason :: String.t()}
  @callback userinfo_sign(payload :: map(), client :: Boruta.Oauth.Client.t()) ::
              jwt :: String.t() | {:error, reason :: String.t()}
  @callback kid_from_private_key(private_pem :: String.t()) :: kid :: String.t()
  @callback userinfo_signature_type(Boruta.Oauth.Client.t()) ::
              userinfo_token_signature_type :: atom()
end
