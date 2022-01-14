defmodule Boruta.Oauth.Introspect do
  @moduledoc """
  Access token introspection
  """

  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.IntrospectRequest
  alias Boruta.Oauth.Token

  @doc """
  Returns corresponding token for the given `Boruta.Oauth.IntrospectRequest`

  Note : Invalid tokens returns an error `{:error, %Error{error: :invalid_access_token, ...}}`. That must be rescued to return `%{"active" => false}` in application implementation.
  ## Examples
      iex> token(%IntrospectRequest{
        client_id: "client_id",
        client_secret: "client_secret",
        token: "token"
      })
      {:ok, %Token{...}}
  """
  @spec token(request :: IntrospectRequest.t()) ::
  {:ok, token :: Token.t()} |
  {:error , error :: Error.t()}
  def token(%IntrospectRequest{client_id: client_id, client_secret: client_secret, token: token}) do
    with {:ok, _client} <- Authorization.Client.authorize(id: client_id, secret: client_secret, grant_type: "introspect"),
         {:ok, token} <- Authorization.AccessToken.authorize(value: token) do
      {:ok, token}
    else
      {:error, %Error{} = error} -> {:error, error}
    end
  end
end
