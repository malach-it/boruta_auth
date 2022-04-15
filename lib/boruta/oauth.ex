defmodule Boruta.OauthModule do
  @moduledoc false

  alias Boruta.Oauth.ResourceOwner

  @callback token(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
  @callback preauthorize(conn :: Plug.Conn.t() | map(), resource_owner :: ResourceOwner.t(), module :: atom()) :: any()
  @callback authorize(conn :: Plug.Conn.t() | map(), resource_owner :: ResourceOwner.t(), module :: atom()) :: any()
  @callback introspect(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
  @callback revoke(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
end

defmodule Boruta.Oauth do
  @moduledoc """
  OAuth requests entrypoint, provides authorization artifacts to clients as stated in [RFC](https://datatracker.ietf.org/doc/html/rfc6749#section-4).

  > __Note__: this module follows inverted heaxagonal architecture, its functions will invoke callbacks of the given module argument and return its result.
  >
  > The definition of those callbacks are provided by either `Boruta.Oauth.Application` or `Boruta.Oauth.AuthorizeApplication`, `Boruta.Oauth.TokenApplication`, `Boruta.Oauth.IntrospectApplication`, and `Boruta.Oauth.RevokeApplication`,
  """

  @behaviour Boruta.OauthModule

  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.AuthorizeResponse
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Introspect
  alias Boruta.Oauth.IntrospectResponse
  alias Boruta.Oauth.Request
  alias Boruta.Oauth.ResourceOwner
  alias Boruta.Oauth.Revoke
  alias Boruta.Oauth.TokenResponse

  @doc """
  Process an token request as stated in [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749).

  Triggers `token_success` in case of success and `token_error` in case of failure from the given `module`. Those functions are described in `Boruta.Oauth.Application` behaviour.
  """
  @spec token(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
  @impl true
  def token(%Plug.Conn{} = conn, module) when is_atom(module) do
    with {:ok, request} <- Request.token_request(conn),
         {:ok, tokens} <- Authorization.token(request),
         %TokenResponse{} = response <- TokenResponse.from_token(tokens) do
      module.token_success(
        conn,
        response
      )
    else
      {:error, %Error{} = error} ->
        module.token_error(conn, error)

      {:error, reason} ->
        error = %Error{
          status: :internal_server_error,
          error: :unknown_error,
          error_description: inspect(reason)
        }

        module.token_error(conn, error)
    end
  end

  @doc """
  Check success of an authorize request as stated in [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749) and [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth).

  Triggers `preauthorize_success` in case of success and `preauthorize_error` in case of failure from the given `module`. Those functions are described in `Boruta.Oauth.Application` behaviour.
  """
  @spec preauthorize(conn :: Plug.Conn.t() | map(), resource_owner :: ResourceOwner.t(), module :: atom()) :: any()
  @impl true
  def preauthorize(%Plug.Conn{} = conn, %ResourceOwner{} = resource_owner, module) when is_atom(module) do
    with {:ok, request} <- Request.authorize_request(conn, resource_owner),
         {:ok, authorization} <- Authorization.preauthorize(request) do
      module.preauthorize_success(
        conn,
        authorization
      )
    else
      {:error, %Error{} = error} ->
        case Request.authorize_request(conn, resource_owner) do
          {:ok, request} ->
            module.preauthorize_error(conn, Error.with_format(error, request))

          _ ->
            module.preauthorize_error(conn, error)
        end
    end
  end

  @doc """
  Process an authorize request as stated in [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749) and [OpenID Connect Core 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth).

  Triggers `authorize_success` in case of success and `authorize_error` in case of failure from the given `module`. Those functions are described in `Boruta.Oauth.Application` behaviour.
  """
  @spec authorize(conn :: Plug.Conn.t() | map(), resource_owner :: ResourceOwner.t(), module :: atom()) :: any()
  @impl true
  def authorize(%Plug.Conn{} = conn, %ResourceOwner{} = resource_owner, module) when is_atom(module) do
    with {:ok, request} <- Request.authorize_request(conn, resource_owner),
         {:ok, tokens} <- Authorization.token(request),
         %AuthorizeResponse{} = response <- AuthorizeResponse.from_tokens(tokens) do
      module.authorize_success(
        conn,
        response
      )
    else
      {:error, %Error{} = error} ->
        formatted_authorize_error(conn, resource_owner, module, error)

      {:error, reason} ->
        error = %Error{
          status: :internal_server_error,
          error: :unknown_error,
          error_description: inspect(reason)
        }

        formatted_authorize_error(conn, resource_owner, module, error)
    end
  end

  defp formatted_authorize_error(conn, resource_owner, module, error) do
    case Request.authorize_request(conn, resource_owner) do
      {:ok, request} ->
        module.authorize_error(conn, Error.with_format(error, request))

      _ ->
        module.authorize_error(conn, error)
    end
  end

  @doc """
  Process a introspect request as stated in [RFC 7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662).

  Triggers `introspect_success` in case of success and `introspect_error` in case of failure from the given `module`. Those functions are described in `Boruta.Oauth.Application` behaviour.
  """
  @spec introspect(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
  @impl true
  def introspect(%Plug.Conn{} = conn, module) when is_atom(module) do
    with {:ok, request} <- Request.introspect_request(conn),
         {:ok, token} <- Introspect.token(request) do
      module.introspect_success(conn, IntrospectResponse.from_token(token))
    else
      {:error, %Error{error: :invalid_access_token} = error} ->
        module.introspect_success(conn, IntrospectResponse.from_error(error))

      {:error, %Error{} = error} ->
        module.introspect_error(conn, error)
    end
  end

  @doc """
  Process a revoke request as stated in [RFC 7009 - OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009).

  Triggers `revoke_success` in case of success and `revoke_error` in case of failure from the given `module`. Those functions are described in `Boruta.Oauth.Application` behaviour.
  """
  @spec revoke(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
  @impl true
  def revoke(%Plug.Conn{} = conn, module) when is_atom(module) do
    with {:ok, request} <- Request.revoke_request(conn),
         :ok <- Revoke.token(request) do
      module.revoke_success(conn)
    else
      {:error, error} ->
        module.revoke_error(conn, error)

      {:error, reason} ->
        error = %Error{
          status: :internal_server_error,
          error: :unknown_error,
          error_description: inspect(reason)
        }

        module.revoke_error(conn, error)
    end
  end
end
