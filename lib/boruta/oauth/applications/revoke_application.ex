defmodule Boruta.Oauth.RevokeApplication do
  @moduledoc """
  OAuth application behaviour - revoke endpoint

  Implement this behaviour in the application layer of your OAuth provider. The callbacks are triggered while calling functions from `Boruta.Oauth` module.
  """

  @doc """
  This function will be triggered in case of success invoking `Boruta.Oauth.revoke/2`
  """
  @callback revoke_success(conn :: Plug.Conn.t()) :: any()
  @doc """
  This function will be triggered in case of failure invoking `Boruta.Oauth.revoke/2`
  """
  @callback revoke_error(conn :: Plug.Conn.t(), oauth_error :: Boruta.Oauth.Error.t()) :: any()
end
