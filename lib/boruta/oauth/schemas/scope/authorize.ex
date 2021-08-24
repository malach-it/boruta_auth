defprotocol Boruta.Oauth.Scope.Authorize do
  def authorized?(scope, schema)
end

defimpl Boruta.Oauth.Scope.Authorize, for: List do
  import Boruta.Config, only: [resource_owners: 0]

  alias Boruta.Oauth.ResourceOwner

  def authorized?(authorized_scopes, scope) do
    Enum.member?(authorized_scopes, scope)
  end
end

defimpl Boruta.Oauth.Scope.Authorize, for: Boruta.Oauth.ResourceOwner do
  import Boruta.Config, only: [resource_owners: 0]

  alias Boruta.Oauth.ResourceOwner

  def authorized?(%ResourceOwner{} = resource_owner, scope) do
    resource_owner_scopes =
      Enum.map(resource_owners().authorized_scopes(resource_owner), fn e -> e.name end)

    Enum.member?(resource_owner_scopes, scope)
  end
end

defimpl Boruta.Oauth.Scope.Authorize, for: Boruta.Oauth.Client do
  alias Boruta.ClientsAdapter
  alias Boruta.ScopesAdapter
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Scope

  def authorized?(%Client{authorize_scope: false}, scope) do
    public_scopes =
      ScopesAdapter.public()
      |> Enum.map(fn scope -> scope.name end)

    Enum.member?(public_scopes, scope)
  end

  def authorized?(%Client{authorize_scope: true} = client, scope) do
    client_scopes =
      Enum.map(
        ClientsAdapter.authorized_scopes(client),
        fn %Scope{name: name} -> name end
      )

    Enum.member?(client_scopes, scope)
  end
end

defimpl Boruta.Oauth.Scope.Authorize, for: Boruta.Oauth.Token do
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.Token

  def authorized?(%Token{scope: token_scope}, scope) do
    token_scopes = Scope.split(token_scope)

    Enum.member?(token_scopes, scope)
  end
end
