defmodule Boruta.Oauth.ResourceOwners do
  @moduledoc """
  Resource owner context
  """

  alias Boruta.Oauth.ResourceOwner

  @doc """
  Returns a resource owner by (username) or (id).
  """
  @callback get_by([username: String.t()] | [sub: String.t()]) ::
              {:ok, resource_owner :: ResourceOwner.t()} | {:error, String.t()}

  @doc """
  Determines if given password is valid for the given resource owner.
  """
  @callback check_password(resource_owner :: ResourceOwner.t(), password :: String.t()) ::
              :ok | {:error, String.t()}

  @doc """
  Returns a list of authorized scopes for a given resource owner. These scopes will be granted is requested for the user.
  """
  @callback authorized_scopes(resource_owner :: ResourceOwner.t()) :: list(Boruta.Oauth.Scope.t())

  @doc """
  Returns `id_token` identity claims for the given resource owner. Those claims will be present in resulting `id_token` of OpenID Connect flows.
  """
  @callback claims(resource_owner :: ResourceOwner.t(), scope :: String.t()) :: claims :: Boruta.Oauth.IdToken.claims()

  @optional_callbacks claims: 2
end
