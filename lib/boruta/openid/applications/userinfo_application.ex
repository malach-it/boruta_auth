defmodule Boruta.Openid.UserinfoApplication do
  @moduledoc """
  Implement this behaviour in the application layer of your OpenID Connect provider.
  This behaviour gives all callbacks triggered invoking `Boruta.Openid.userinfo/2` functions.
  """

  @doc """
  This function will be triggered in case of success invoking `Boruta.Oauth.userinfo/2`
  """
  @callback userinfo_fetched(Plug.Conn.t(), map()) :: any()

  @doc """
  This function will be triggered when request is unauthorized invoking `Boruta.Oauth.userinfo/2`
  """
  @callback unauthorized(Plug.Conn.t(), Boruta.Oauth.Error.t()) :: any()
end
