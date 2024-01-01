defmodule Boruta.Openid.CredentialApplication do
  @moduledoc """
  Implement this behaviour in the application layer of your OpenID Connect provider.
  This behaviour gives all callbacks triggered invoking `Boruta.Openid.credential/3` function.
  """

  @doc """
  This function will be triggered in case of success invoking `Boruta.Openid.credential/3`
  """
  @callback credential_created(conn :: Plug.Conn.t(), credential :: Boruta.Openid.CredentialResponse.t()) ::
              any()
  @doc """
  This function will be triggered in case of failure invoking `Boruta.Openid.credential/3`
  """
  @callback credential_failure(conn :: Plug.Conn.t(), error :: Boruta.Oauth.Error.t()) ::
              any()
end
