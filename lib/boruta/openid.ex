defmodule Boruta.OpenidModule do
  @moduledoc false
  @callback jwks(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
end

defmodule Boruta.Openid do
  @moduledoc """
  Openid requests entrypoint, provides additional artifacts to OAuth as stated in [Openid Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).

  > __Note__: this module follows inverted heaxagonal architecture, its functions will invoke callbacks of the given module argument and return its result.
  >
  > The definition of those callbacks are provided by either `Boruta.Openid.Application` or `Boruta.Oauth.JwksApplication`
  """

  import Boruta.Config, only: [clients: 0]

  def jwks(conn, module) do
    jwk_keys = clients().list_clients_jwk()

    module.jwk_list(conn, jwk_keys)
  end
end
