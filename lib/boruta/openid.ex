defmodule Boruta.OpenidModule do
  @moduledoc false
  @callback jwks(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
  @callback userinfo(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
end

defmodule Boruta.Openid do
  @moduledoc """
  Openid requests entrypoint, provides additional artifacts to OAuth as stated in [Openid Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html).

  > __Note__: this module follows inverted heaxagonal architecture, its functions will invoke callbacks of the given module argument and return its result.
  >
  > The definition of those callbacks are provided by either `Boruta.Openid.Application` or `Boruta.Openid.JwksApplication` and `Boruta.Openid.UserinfoApplication`
  """

  alias Boruta.ClientsAdapter
  alias Boruta.Oauth.Authorization.AccessToken
  alias Boruta.Oauth.BearerToken
  alias Boruta.Oauth.Token
  alias Boruta.Openid.UserinfoResponse

  def jwks(conn, module) do
    jwk_keys = ClientsAdapter.list_clients_jwk()

    module.jwk_list(conn, jwk_keys)
  end

  def userinfo(conn, module) do
    with {:ok, access_token} <- BearerToken.extract_token(conn),
         {:ok, token} <- AccessToken.authorize(value: access_token),
         {:ok, userinfo} <- Token.userinfo(token) do
      module.userinfo_fetched(conn, UserinfoResponse.from_userinfo(userinfo, token.client))
    else
      {:error, error} ->
        module.unauthorized(conn, error)
    end
  end

  def register_client(conn, registration_params, module) do
    case registration_params
         |> parse_registration_params(registration_params)
         |> ClientsAdapter.create_client() do
      {:ok, client} ->
        module.client_registered(conn, client)

      {:error, changeset} ->
        module.registration_failure(conn, changeset)
    end
  end

  defp parse_registration_params(params, %{jwks: %{keys: [jwk]}} = acc) do
    parse_registration_params(
      Map.put(params, :jwk, jwk),
      Map.delete(acc, :jwks)
    )
  end

  defp parse_registration_params(params, %{client_name: name} = acc) do
    parse_registration_params(
      Map.put(params, :name, name),
      Map.delete(acc, :client_name)
    )
  end

  defp parse_registration_params(params, %{token_endpoint_auth_method: method} = acc) do
    parse_registration_params(
      Map.put(params, :token_endpoint_auth_methods, [method]),
      Map.delete(acc, :token_endpoint_auth_method)
    )
  end

  defp parse_registration_params(params, _), do: params
end
