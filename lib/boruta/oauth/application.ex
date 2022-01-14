defmodule Boruta.Oauth.Application do
  @moduledoc """
  Implement this behaviour in the application layer of your OAuth / OpenID Connect provider.
  This behaviour gives all callbacks triggered invoking `Boruta.Oauth` module functions.

  > __Note__: This behaviour is splitted into `Boruta.Oauth.AuthorizeApplication`, `Boruta.Oauth.TokenApplication`, `Boruta.Oauth.IntrospectApplication`, and `Boruta.Oauth.RevokeApplication` providing utilities to implement the different OAuth / OpenID Connect endpoints independently.
  """

  @doc """
  This function will be triggered in case of success invoking `Boruta.Oauth.token/2`
  """
  @callback token_success(conn :: Plug.Conn.t(), token_response :: Boruta.Oauth.TokenResponse.t()) ::
              any()
  @doc """
  This function will be triggered in case of failure invoking `Boruta.Oauth.token/2`
  """
  @callback token_error(conn :: Plug.Conn.t(), oauth_error :: Boruta.Oauth.Error.t()) :: any()

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
  @callback preauthorize_error(conn :: Plug.Conn.t(), oauth_error :: Boruta.Oauth.Error.t()) ::
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
  @callback authorize_error(conn :: Plug.Conn.t(), oauth_error :: Boruta.Oauth.Error.t()) :: any()

  @doc """
  This function will be triggered in case of success invoking `Boruta.Oauth.introspect/2`
  """
  @callback introspect_success(
              conn :: Plug.Conn.t(),
              introspect_response :: Boruta.Oauth.IntrospectResponse.t()
            ) :: any()
  @doc """
  This function will be triggered in case of failure invoking `Boruta.Oauth.introspect/2`
  """
  @callback introspect_error(conn :: Plug.Conn.t(), oauth_error :: Boruta.Oauth.Error.t()) ::
              any()

  @doc """
  This function will be triggered in case of success invoking `Boruta.Oauth.revoke/2`
  """
  @callback revoke_success(conn :: Plug.Conn.t()) :: any()
  @doc """
  This function will be triggered in case of failure invoking `Boruta.Oauth.revoke/2`
  """
  @callback revoke_error(conn :: Plug.Conn.t(), oauth_error :: Boruta.Oauth.Error.t()) :: any()

  @optional_callbacks preauthorize_success: 2, preauthorize_error: 2
end
