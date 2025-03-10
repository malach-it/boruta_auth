defmodule Boruta.Openid.DirectPostApplication do
  @moduledoc """
  Implement this behaviour in the application layer of your OpenID SiopV2 provider.
  This behaviour gives all callbacks triggered invoking `Boruta.Openid.direct_post/3` function.
  """

  @callback direct_post_success(
              conn :: Plug.Conn.t() | map(),
              response :: any(),
              token :: Boruta.Oauth.Token.t()
            ) :: any()
  @callback code_not_found(conn :: Plug.Conn.t()) :: any()
  @callback authentication_failure(conn :: Plug.Conn.t(), error :: Boruta.Oauth.Error.t()) ::
              any()
end
