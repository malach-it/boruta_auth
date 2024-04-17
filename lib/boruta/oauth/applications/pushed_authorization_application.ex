defmodule Boruta.Oauth.PushedAuthorizationRequestApplication do
  @moduledoc """
  OAuth application behaviour - pushed authorization endpoint

  Implement this behaviour in the application layer of your OAuth provider. The callbacks are triggered while calling functions from `Boruta.Oauth` module.
  """

  @doc """
  This function will be triggered in case of success invoking `Boruta.Oauth.pushed_authorization_request/2`
  """
  @callback request_stored(
              conn :: Plug.Conn.t(),
              response :: Boruta.Oauth.PushedAuthorizationResponse.t()
            ) ::
              any()
  @doc """
  This function will be triggered in case of failure invoking `Boruta.Oauth.pushed_authorization_request/2`
  """
  @callback pushed_authorization_error(
              conn :: Plug.Conn.t(),
              error :: Boruta.Oauth.Error.t()
            ) ::
              any()
end
