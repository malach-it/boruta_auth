defmodule Boruta.Oauth.Clients do
  @moduledoc """
  Client context
  """

  @doc """
  Returns a `Boruta.Oauth.Client` by either id and secret ou by id and redirect_uri.
  """
  @callback get_by(
    [id: id :: String.t()] |
    [id: id :: String.t(), redirect_uri: String.t()]
  ) :: client :: Boruta.Oauth.Client.t() | nil

  @doc """
  Returns client authorized scopes. The scopes will be granted for every requests to the given client.
  """
  @callback authorized_scopes(client :: Boruta.Oauth.Client.t()) :: list(Boruta.Oauth.Scope.t())
end
