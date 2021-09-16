defprotocol Boruta.Oauth.Scope.Authorize do
  @moduledoc false

  def authorized?(scope, schema, public_scopes \\ [])
end

defimpl Boruta.Oauth.Scope.Authorize, for: List do
  import Boruta.Config, only: [resource_owners: 0]

  alias Boruta.Oauth.ResourceOwner

  def authorized?(authorized_scopes, scope, _public_scopes \\ []) do
    Enum.member?(authorized_scopes, scope)
  end
end

defimpl Boruta.Oauth.Scope.Authorize, for: Boruta.Oauth.ResourceOwner do
  import Boruta.Config, only: [resource_owners: 0]

  alias Boruta.Oauth.ResourceOwner

  def authorized?(%ResourceOwner{} = resource_owner, scope, _public_scopes \\ []) do
    resource_owner_scopes =
      Enum.map(resource_owners().authorized_scopes(resource_owner), fn e -> e.name end)

    Enum.member?(resource_owner_scopes, scope)
  end
end

defimpl Boruta.Oauth.Scope.Authorize, for: Boruta.Oauth.Client do
  alias Boruta.ClientsAdapter
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Scope

  def authorized?(client, scope, public_scopes \\ [])
  def authorized?(%Client{authorize_scope: false}, scope, public_scopes) do
    Enum.member?(public_scopes, scope)
  end

  def authorized?(%Client{authorize_scope: true} = client, scope, _public_scopes) do
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

  def authorized?(%Token{scope: token_scope}, scope, _public_scopes \\ []) do
    token_scopes = Scope.split(token_scope)

    Enum.member?(token_scopes, scope)
  end
end
