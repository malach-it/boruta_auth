defprotocol Boruta.Ecto.OauthMapper do
  @moduledoc false

  @spec to_oauth_schema(schema :: struct()) :: oauth_schema :: struct()
  def to_oauth_schema(schema)
end

defimpl Boruta.Ecto.OauthMapper, for: Boruta.Ecto.Token do
  import Boruta.Config, only: [repo: 0, resource_owners: 0]

  alias Boruta.Oauth
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Ecto
  alias Boruta.Ecto.Clients
  alias Boruta.Ecto.OauthMapper

  def to_oauth_schema(%Ecto.Token{} = token) do
    client =
      case Clients.get_client(token.client_id) do
        %Oauth.Client{} = client -> client
        _ -> nil
      end

    resource_owner =
      token.resource_owner ||
        with "" <> sub <- token.sub,
             false <- Regex.match?(~r/^did\:/, sub),
             {:ok, resource_owner} <- resource_owners().get_by(sub: sub) do
          resource_owner
        else
          # NOTE resource owner is public (sub is a did)
          true -> %ResourceOwner{sub: token.sub}
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

defimpl Boruta.Ecto.OauthMapper, for: Boruta.Ecto.AuthorizationRequest do
  alias Boruta.Ecto
  alias Boruta.Oauth

  def to_oauth_schema(%Ecto.AuthorizationRequest{} = request) do
    struct(Oauth.AuthorizationRequest, Map.from_struct(request))
  end
end

defimpl Boruta.Ecto.OauthMapper, for: Boruta.Ecto.Credential do
  alias Boruta.Ecto
  alias Boruta.Openid

  def to_oauth_schema(%Ecto.Credential{} = credential) do
    struct(Openid.Credential, Map.from_struct(credential))
  end
end
