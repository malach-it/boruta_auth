defmodule Boruta.Openid.ApplicationMock do
  @moduledoc false
  @behaviour Boruta.Openid.Application

  @impl Boruta.Openid.Application
  def jwk_list(_conn, jwk_keys), do: {:jwk_list, jwk_keys}
end
