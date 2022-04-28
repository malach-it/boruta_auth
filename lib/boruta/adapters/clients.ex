defmodule Boruta.ClientsAdapter do
  @moduledoc """
  Encapsulate injected `Boruta.Oauth.Clients` adapter in context configuration
  """

  @behaviour Boruta.Oauth.Clients

  import Boruta.Config, only: [clients: 0]

  def get_client(id), do: clients().get_client(id)
  def authorized_scopes(params), do: clients().authorized_scopes(params)
  def list_clients_jwk, do: clients().list_clients_jwk()
end
