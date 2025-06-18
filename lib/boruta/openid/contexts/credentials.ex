defmodule Boruta.Openid.Credentials do
  @moduledoc """
  Credential context
  """

  @doc """
  Stores a credential for later use (eg. defered flow)
  """
  @callback get_by(access_token: access_token :: String.t()) ::
              credential :: Boruta.Openid.Credential.t() | nil

  @doc """
  Stores a credential for later use (eg. defered flow)
  """
  @callback create_credential(
              credential :: Boruta.Openid.Credential.t(),
              token :: Boruta.Oauth.Token.t()
            ) ::
              {:ok, credential :: Boruta.Openid.Credential.t()}
              | {:error, Ecto.Changeset.t()}
end
