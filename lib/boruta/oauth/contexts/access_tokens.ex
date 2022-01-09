defmodule Boruta.Oauth.AccessTokens do
  @moduledoc """
  Access token context
  """

  @doc """
  Returns a `Boruta.Oauth.Token` either by `value` or `refresh_token`.
  """
  @callback get_by(
    [value: String.t()] |
    [refresh_token: String.t()]
  ) :: token :: Boruta.Oauth.Token.t() | nil

  @doc """
  Persists a token with the given params.
  """
  @callback create(params :: %{
    :client => Boruta.Oauth.Client.t(),
    :sub => String.t(),
    optional(:redirect_uri) => String.t(),
    :scope => String.t(),
    optional(:state) => String.t(),
    optional(:previous_token) => String.t()
  }, options :: [
    refresh_token: boolean()
  ]) :: token :: Boruta.Oauth.Token.t() | {:error, reason :: term()}

  @doc """
  Revokes the given `Boruta.Oauth.Token`.
  """
  @callback revoke(
    token :: Boruta.Oauth.Token.t()
  ) :: {:ok, Boruta.Oauth.Token.t()} | {:error, reason :: term()}
end
