defmodule Boruta.Oauth.Clients do
  @moduledoc """
  Client context
  """

  @doc """
  Returns a `Boruta.Oauth.Client` given id.
  """
  @callback get_client(id :: any()) :: client :: Boruta.Oauth.Client.t() | nil

  @doc """
  Returns client authorized scopes. The scopes will be granted for every requests to the given client.
  """
  @callback authorized_scopes(client :: Boruta.Oauth.Client.t()) :: list(Boruta.Oauth.Scope.t())

  @doc """
  Returns all clients jwk public keys
  """
  @callback list_clients_jwk() :: list(%JOSE.JWK{})

  @optional_callbacks [list_clients_jwk: 0]
end
