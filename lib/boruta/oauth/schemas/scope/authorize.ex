defprotocol Boruta.Oauth.Scope.Authorize do
  @moduledoc false

  def authorized_scopes(schema, scope, public_scopes \\ [])
end

defimpl Boruta.Oauth.Scope.Authorize, for: List do
  import Boruta.Config, only: [resource_owners: 0]

  alias Boruta.Oauth.ResourceOwner

  def authorized_scopes(authorized_scopes, scopes, _public_scopes \\ []) do
    scopes -- (scopes -- authorized_scopes) # intersection
  end
end

defimpl Boruta.Oauth.Scope.Authorize, for: Boruta.Oauth.ResourceOwner do
  import Boruta.Config, only: [resource_owners: 0]

  alias Boruta.Oauth.ResourceOwner

  def authorized_scopes(%ResourceOwner{} = resource_owner, scopes, _public_scopes \\ []) do
    authorized_scopes =
      Enum.map(resource_owners().authorized_scopes(resource_owner), fn e -> e.name end)

    scopes -- (scopes -- authorized_scopes) # intersection
  end
end

defimpl Boruta.Oauth.Scope.Authorize, for: Boruta.Oauth.Client do
  alias Boruta.ClientsAdapter
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Scope

  def authorized_scopes(client, scope, public_scopes \\ [])

  def authorized_scopes(%Client{authorize_scope: false}, scopes, public_scopes) do
    scopes -- (scopes -- public_scopes) # intersection
  end

  def authorized_scopes(%Client{authorize_scope: true} = client, scopes, _public_scopes) do
    authorized_scopes =
      Enum.map(
        ClientsAdapter.authorized_scopes(client),
        fn %Scope{name: name} -> name end
      )

    scopes -- (scopes -- authorized_scopes) # intersection
  end
end

defimpl Boruta.Oauth.Scope.Authorize, for: Boruta.Oauth.Token do
  alias Boruta.Oauth.Scope
  alias Boruta.Oauth.Token

  def authorized_scopes(%Token{scope: token_scope}, scopes, _public_scopes \\ []) do
    authorized_scopes = Scope.split(token_scope)

    scopes -- (scopes -- authorized_scopes) # intersection
  end
end
