defmodule Boruta.ClientsAdapter do
  @moduledoc """
  Encapsulate injected clients adapter in context configuration.
  """

  @behaviour Boruta.Oauth.Clients

  import Boruta.Config, only: [clients: 0]

  defdelegate get_by(params), to: clients()
  defdelegate authorized_scopes(params), to: clients()
end
