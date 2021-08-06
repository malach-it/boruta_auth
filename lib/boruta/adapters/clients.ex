defmodule Boruta.ClientsAdapter do
  @moduledoc """
  Encapsulate injected clients adapter in context configuration.
  """

  @behaviour Boruta.Oauth.Clients

  import Boruta.Config, only: [clients: 0]

  def get_by(params), do: clients().get_by(params)
  def authorized_scopes(params), do: clients().authorized_scopes(params)
end
