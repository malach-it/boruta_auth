defmodule Boruta.Oauth.IntrospectApplication do
  @moduledoc """
  OAuth application behaviour - introspect endpoint

  Implement this behaviour in the application layer of your OAuth provider. The callbacks are triggered while calling functions from `Boruta.Oauth` module.
  """

  @doc """
  This function will be triggered in case of success triggering `Boruta.Oauth.introspect/2`
  """
  @callback introspect_success(
              conn :: Plug.Conn.t(),
              introspect_response :: Boruta.Oauth.IntrospectResponse.t()
            ) :: any()
  @doc """
  This function will be triggered in case of failure triggering `Boruta.Oauth.introspect/2`
  """
  @callback introspect_error(conn :: Plug.Conn.t(), oauth_error :: Boruta.Oauth.Error.t()) ::
              any()
end
