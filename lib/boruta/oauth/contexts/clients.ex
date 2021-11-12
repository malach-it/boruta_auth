defmodule Boruta.Oauth.Clients do
  @moduledoc """
  Client context
  """

  @doc """
  Returns a `Boruta.Oauth.Client` by id.
  """
  @callback get_by(
    [id: id :: String.t()]
  ) :: client :: Boruta.Oauth.Client.t() | nil

  @doc """
  Returns client authorized scopes. The scopes will be granted for every requests to the given client.
  """
  @callback authorized_scopes(client :: Boruta.Oauth.Client.t()) :: list(Boruta.Oauth.Scope.t())
end
