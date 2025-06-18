defmodule Boruta.Openid.Signatures do
  @moduledoc """
  Utilities to sign verifiable credentials
  """

  @doc """
  Signs the given payload according tot the given client and generates a verifiable credential
  """
  @callback verifiable_credential_sign(
              payload :: map(),
              client :: Boruta.Oauth.Client.t(),
              format :: String.t()
            ) ::
              jwt :: String.t() | {:error, reason :: String.t()}
end
