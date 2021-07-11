defmodule Boruta.Oauth do
  @moduledoc """
  Boruta OAuth entrypoint, handles OAuth requests.

  Note : this module works in association with `Boruta.Oauth.Application` behaviour
  """

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
  def token(conn, module) do
    with {:ok, request} <- Request.token_request(conn),
         {:ok, token} <- Authorization.token(request) do
      module.token_success(
        conn,
        TokenResponse.from_token(token)
      )
    else
      {:error, %Error{} = error} ->
        module.token_error(conn, error)
    end
  end

  @doc """
  Process an authorize request as stated in [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749).

  Triggers `preauthorize_success` in case of success and `preauthorize_error` in case of failure from the given `module`. Those functions are described in `Boruta.Oauth.Application` behaviour.
  """
  @spec preauthorize(
          conn :: Plug.Conn.t() | map(),
          resource_owner :: ResourceOwner.t(),
          module :: atom()
        ) :: any()
  def preauthorize(conn, resource_owner, module) do
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
  Process an authorize request and returns a token as stated in [RFC 6749 - The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749).

  Triggers `authorize_success` in case of success and `authorize_error` in case of failure from the given `module`. Those functions are described in `Boruta.Oauth.Application` behaviour.
  """
  @spec authorize(
          conn :: Plug.Conn.t() | map(),
          resource_owner :: ResourceOwner.t(),
          module :: atom()
        ) :: any()
  def authorize(conn, resource_owner, module) do
    with {:ok, request} <- Request.authorize_request(conn, resource_owner),
         {:ok, tokens} <- Authorization.token(request) do
      module.authorize_success(
        conn,
        AuthorizeResponse.from_tokens(tokens)
      )
    else
      {:error, %Error{} = error} ->
        case Request.authorize_request(conn, resource_owner) do
          {:ok, request} ->
            module.authorize_error(conn, Error.with_format(error, request))

          _ ->
            module.authorize_error(conn, error)
        end
    end
  end

  @doc """
  Process a introspect request as stated in [RFC 7662 - OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662).

  Triggers `introspect_success` in case of success and `introspect_error` in case of failure from the given `module`. Those functions are described in `Boruta.Oauth.Application` behaviour.
  """
  @spec introspect(conn :: Plug.Conn.t() | map(), module :: atom()) :: any()
  def introspect(conn, module) do
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
  def revoke(conn, module) do
    with {:ok, request} <- Request.revoke_request(conn),
         :ok <- Revoke.token(request) do
      module.revoke_success(conn)
    else
      {:error, error} ->
        module.revoke_error(conn, error)
    end
  end
end
