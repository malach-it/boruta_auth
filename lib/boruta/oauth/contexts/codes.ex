defmodule Boruta.Oauth.Codes do
  @moduledoc """
  Code context
  """

  @doc """
  Returns a `Boruta.Oauth.Token` by `value` and `redirect_uri`.
  """
  @callback get_by(
    params :: [value: String.t()]
  ) :: token :: Boruta.Oauth.Token | nil
  @callback get_by(
    params :: [value: String.t(), redirect_uri: String.t()]
  ) :: token :: Boruta.Oauth.Token | nil

  @doc """
  Persists a token according to given params.
  """
  @callback create(params :: %{
    :client => Boruta.Oauth.Client.t(),
    :sub => String.t(),
    :redirect_uri => String.t(),
    :scope => String.t(),
    :state => String.t(),
    :code_challenge => String.t(),
    :code_challenge_method => String.t(),
    :authorization_details => list(map()),
    optional(:resource_owner) => Boruta.Oauth.ResourceOwner.t()
  }) :: code :: Boruta.Oauth.Token.t() | {:error, reason :: term()}

  @doc """
  Revokes the given `Boruta.Oauth.Token` code.
  """
  @callback revoke(
    token :: Boruta.Oauth.Token.t()
  ) :: {:ok, Boruta.Oauth.Token.t()} | {:error, reason :: term()}

  @doc """
  Revokes the the previouly issued token given `Boruta.Oauth.Token` code.
  """
  @callback revoke_previous_token(
    token :: Boruta.Oauth.Token.t()
  ) :: {:ok, Boruta.Oauth.Token.t()} | {:error, reason :: term()}
end
