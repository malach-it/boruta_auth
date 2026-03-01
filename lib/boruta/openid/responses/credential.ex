defmodule Boruta.Openid.CredentialResponse do
  @moduledoc """
  Response in case of delivrance of verifiable credential
  """

  alias Boruta.CodesAdapter
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Token

  @enforce_keys [:format, :credential]
  defstruct format: nil,
    token: nil,
    credential: nil,
    encrypted_response: nil

  @type t :: %__MODULE__{
    format: String.t(),
    token: Boruta.Oauth.Token.t(),
    credential: String.t(),
    encrypted_response: String.t() | nil
  }

  def from_credential(credential, token) do
    encrypted_response = with "" <> previous_code <- token.previous_code,
      %Token{} = token <- CodesAdapter.get_by(value: previous_code) do
      Client.Crypto.encrypt(%{
        format: credential.format,
        credential: credential.credential,
        # TODO compute and store c_nonce
        c_nonce: "boruta",
        c_nonce_expires_in: 3600
      }, token.client_encryption_key, token.client_encryption_alg)
    else
      _ -> nil
    end
    %__MODULE__{
      credential: credential.credential,
      token: token,
      format: credential.format,
      encrypted_response: encrypted_response
    }
  end
end
