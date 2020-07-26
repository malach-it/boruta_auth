defmodule Boruta.Oauth.ResourceOwners do
  @moduledoc """
  Resource owner context
  """
  @doc """
  Returns a resource owner by (username, password) or (id). Returns nil for non matching results.
  """
  @callback get_by([username: String.t()] | [sub: String.t()]) ::
    {:ok, resource_owner :: struct()} | {:error, String.t()}

  @doc """
  Determines if given password is correct.
  """
  @callback check_password(resource_owner :: struct(), password :: String.t()) :: :ok | {:error, String.t()}

  @doc """
  Returns resource owner username value.
  """
  @callback username(resource_owner :: struct()) :: String.t() | nil

  @doc """
  Returns resource owner sub value.
  """
  @callback sub(resource_owner :: struct()) :: String.t() | nil

  @doc """
  Returns a list of authorized scopes for a given resource owner. These scopes will be granted is requested for the user.
  """
  @callback authorized_scopes(resource_owner :: struct()) :: list(Boruta.Oauth.Scope.t())

  @doc """
  Returns true whenever the given resource owner is persisted.
  """
  @callback persisted?(resource_owner :: struct()) :: boolean()
end
