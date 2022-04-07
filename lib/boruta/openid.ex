defmodule Boruta.OpenidModule do
  @moduledoc false
  @callback jwks(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
end

defmodule Boruta.Openid do
  @moduledoc """
  Openid requests entrypoint, provides additional artifacts to OAuth as stated in [Openid Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).

  > __Note__: this module follows inverted heaxagonal architecture, its functions will invoke callbacks of the given module argument and return its result.
  >
  > The definition of those callbacks are provided by either `Boruta.Openid.Application` or `Boruta.Oauth.JwksApplication`
  """

  import Boruta.Config, only: [clients: 0, resource_owners: 0]

  alias Boruta.Oauth.Authorization.AccessToken
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Token

  def jwks(conn, module) do
    jwk_keys = clients().list_clients_jwk()

    module.jwk_list(conn, jwk_keys)
  end

  def userinfo(conn, module) do
    with [authorization_header] <- Plug.Conn.get_req_header(conn, "authorization"),
         [_authorization_header, access_token] <-
           Regex.run(~r/Bearer (.+)/, authorization_header),
         {:ok, %Token{resource_owner: %ResourceOwner{} = resource_owner, scope: scope}} <-
           AccessToken.authorize(value: access_token) do
      userinfo = resource_owner
      |> resource_owners().claims(scope)
      |> Map.put(:sub, resource_owner.sub)

      module.userinfo_fetched(conn, userinfo)
    else
      {:error, error} ->
        module.unauthorized(conn, error)

      _ ->
        module.unauthorized(conn, %Error{
          status: :bad_request,
          error: :invalid_bearer,
          error_description: "Invalid bearer from Authorization header."
        })
    end
  end
end
