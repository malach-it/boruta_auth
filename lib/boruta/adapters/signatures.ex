defmodule Boruta.SignaturesAdapter do
  @moduledoc """
  Encapsulate injected `Boruta.Oauth.Signatures` and `Boruta.Openid.Signatures` adapter in context configuration
  """

  @behaviour Boruta.Oauth.Signatures
  @behaviour Boruta.Openid.Signatures

  import Boruta.Config, only: [signatures: 0]

  @impl Boruta.Oauth.Signatures
  def signature_algorithms, do: signatures().signature_algorithms()

  @impl Boruta.Oauth.Signatures
  def hash_alg(client), do: signatures().hash_alg(client)

  @impl Boruta.Oauth.Signatures
  def hash_binary_size(client), do: signatures().hash_binary_size(client)

  @impl Boruta.Oauth.Signatures
  def hash(string, client), do: signatures().hash(string, client)

  @impl Boruta.Oauth.Signatures
  def id_token_sign(payload, client), do: signatures().id_token_sign(payload, client)

  @impl Boruta.Oauth.Signatures
  def verify_id_token_signature(id_token, jwk),
    do: signatures().verify_id_token_signature(id_token, jwk)

  @impl Boruta.Oauth.Signatures
  def userinfo_sign(payload, client), do: signatures().userinfo_sign(payload, client)

  @impl Boruta.Openid.Signatures
  def verifiable_credential_sign(payload, client),
    do: signatures().verifiable_credential_sign(payload, client)

  @impl Boruta.Oauth.Signatures
  def kid_from_private_key(private_pem), do: signatures().kid_from_private_key(private_pem)

  @impl Boruta.Oauth.Signatures
  def userinfo_signature_type(client), do: signatures().userinfo_signature_type(client)
end
