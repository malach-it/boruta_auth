defmodule Boruta.Oauth.Codes do
  @moduledoc """
  Code context
  """

  @doc """
  Returns a `Boruta.Oauth.Token` by `value` and `redirect_uri`.
  """
  @callback get_by(params :: [id: String.t()]) :: token :: Boruta.Oauth.Token.t() | nil
  @callback get_by(params :: [value: String.t()]) :: token :: Boruta.Oauth.Token.t() | nil
  @callback get_by(params :: [value: String.t(), redirect_uri: String.t()]) ::
              token :: Boruta.Oauth.Token.t() | nil

  @doc """
  Persists a token according to given params.
  """
  @callback create(
              params :: %{
                :client => Boruta.Oauth.Client.t(),
                :sub => String.t(),
                :redirect_uri => String.t(),
                :scope => String.t(),
                :state => String.t(),
                :code_challenge => String.t(),
                :code_challenge_method => String.t(),
                :authorization_details => list(map()) | nil,
                :presentation_definition => map() | nil,
                optional(:resource_owner) => Boruta.Oauth.ResourceOwner.t()
              }
            ) :: code :: Boruta.Oauth.Token.t() | {:error, reason :: term()}

  @doc """
  Revokes the given `Boruta.Oauth.Token` code.
  """
  @callback revoke(Boruta.Oauth.Token.t() | list(Boruta.Oauth.Token.t())) ::
              {:ok, Boruta.Oauth.Token.t()} | {:error, reason :: term()}

  @doc """
  Updates code client encryption
  """
  @callback update_client_encryption(
    token :: Boruta.Oauth.Token.t(),
    params :: map()
  ) :: {:ok, Boruta.Oauth.Token.t()} | {:error, reason :: term()}

  @doc """
  Revokes the the previouly issued token given a `Boruta.Oauth.Token` code.
  """
  @callback revoke_previous_token(token :: Boruta.Oauth.Token.t()) ::
              {:ok, Boruta.Oauth.Token.t()} | {:error, reason :: term()}

  @doc """
  Updates given `Boruta.Oauth.Token` code sub value. The resulting token is of type "code".
  """
  @callback update_sub(preauthorized_code :: Boruta.Oauth.Token.t(), sub :: String.t()) ::
              {:ok, preauthorized_code :: Boruta.Oauth.Token.t()} | {:error, reason :: term()}

  @doc """
  Returns the code chain previously issued given a `Boruta.Oauth.Token` code.
  """
  @callback code_chain(token :: Boruta.Oauth.Token.t()) ::
              list(token :: Boruta.Oauth.Token.t()) | {:error, reason :: String.t()}
end
