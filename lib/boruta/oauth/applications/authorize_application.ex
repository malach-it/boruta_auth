defmodule Boruta.Oauth.AuthorizeApplication do
  @moduledoc """
  OAuth application behaviour - authorize endpoint

  Implement this behaviour in the application layer of your OAuth provider. The callbacks are triggered while calling functions from `Boruta.Oauth` module.
  """

  @doc """
  This function will be triggered in case of success invoking `Boruta.Oauth.preauthorize/3`
  """
  @callback preauthorize_success(
              conn :: Plug.Conn.t(),
              authorization :: Boruta.Oauth.AuthorizationSuccess.t()
            ) :: any()
  @doc """
  This function will be triggered in case of failure invoking `Boruta.Oauth.preauthorize/3`
  """
  @callback preauthorize_error(
              conn :: Plug.Conn.t(),
              oauth_error :: Boruta.Oauth.Error.t()
            ) ::
              any()

  @doc """
  This function will be triggered in case of success invoking `Boruta.Oauth.authorize/3`
  """
  @callback authorize_success(
              conn :: Plug.Conn.t(),
              authorize_response :: Boruta.Oauth.AuthorizeResponse.t()
            ) :: any()
  @doc """
  This function will be triggered in case of failure invoking `Boruta.Oauth.authorize/3`
  """
  @callback authorize_error(conn :: Plug.Conn.t(), oauth_error :: Boruta.Oauth.Error.t()) ::
              any()

  @optional_callbacks preauthorize_success: 2, preauthorize_error: 2
end
