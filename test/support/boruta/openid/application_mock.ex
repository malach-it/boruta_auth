defmodule Boruta.Openid.ApplicationMock do
  @moduledoc false
  @behaviour Boruta.Openid.Application

  @impl Boruta.Openid.Application
  def jwk_list(_conn, jwk_keys), do: {:jwk_list, jwk_keys}

  @impl Boruta.Openid.Application
  def userinfo_fetched(_conn, userinfo), do: {:userinfo_fetched, userinfo}

  @impl Boruta.Openid.Application
  def unauthorized(_conn, error), do: {:unauthorized, error}
end
