defprotocol Boruta.Ecto.OauthMapper do
  @moduledoc false

  @fallback_to_any true
  @spec to_oauth_schema(schema :: struct()) :: oauth_schema :: struct()
  def to_oauth_schema(schema)
end

defimpl Boruta.Ecto.OauthMapper, for: Any do
  def to_oauth_schema(schema), do: schema
end

defimpl Boruta.Ecto.OauthMapper, for: Boruta.Ecto.Token do
  import Boruta.Config, only: [repo: 0, resource_owners: 0]

  alias Boruta.Oauth
  alias Boruta.Ecto
  alias Boruta.Ecto.OauthMapper

  def to_oauth_schema(%Ecto.Token{} = token) do
    token = repo().preload(token, [:client])
    client = OauthMapper.to_oauth_schema(token.client)
    resource_owner = with "" <> sub <- token.sub, # token is linked to a resource_owner
      {:ok, resource_owner} <- resource_owners().get_by(sub: sub) do
      resource_owner
    else
      _ -> nil
    end

    struct(
      Oauth.Token,
      Map.merge(
        Map.from_struct(token),
        %{
          client: client,
          resource_owner: resource_owner
        }
      )
    )
  end
end

defimpl Boruta.Ecto.OauthMapper, for: Boruta.Ecto.Client do
  import Boruta.Config, only: [repo: 0]

  alias Boruta.Oauth
  alias Boruta.Ecto
  alias Boruta.Ecto.OauthMapper

  def to_oauth_schema(%Ecto.Client{} = client) do
    client = repo().preload(client, :authorized_scopes)

    struct(
      Oauth.Client,
      Map.merge(
        Map.from_struct(client),
        %{
          authorized_scopes:
            Enum.map(client.authorized_scopes, fn scope ->
              OauthMapper.to_oauth_schema(scope)
            end)
        }
      )
    )
  end
end

defimpl Boruta.Ecto.OauthMapper, for: Boruta.Ecto.Scope do
  alias Boruta.Ecto
  alias Boruta.Oauth

  def to_oauth_schema(%Ecto.Scope{} = scope) do
    struct(Oauth.Scope, Map.from_struct(scope))
  end
end
