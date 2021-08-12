defmodule Boruta.Oauth.TokenApplication do
  @moduledoc """
  OAuth application behaviour - token endpoint

  Implement this behaviour in the application layer of your OAuth provider. The callbacks are triggered while calling functions from `Boruta.Oauth` module.
  """

  @doc """
  This function will be triggered in case of success invoking `Boruta.Oauth.token/2`
  """
  @callback token_success(
              conn :: Plug.Conn.t(),
              token_response :: Boruta.Oauth.TokenResponse.t()
            ) ::
              any()
  @doc """
  This function will be triggered in case of failure invoking `Boruta.Oauth.token/2`
  """
  @callback token_error(conn :: Plug.Conn.t(), oauth_error :: Boruta.Oauth.Error.t()) :: any()
end
