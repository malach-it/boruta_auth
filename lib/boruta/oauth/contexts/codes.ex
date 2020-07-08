defmodule Boruta.Oauth.Codes do
  @moduledoc """
  Code context
  """

  @doc """
  Returns a `Boruta.Oauth.Token` by `value` and `redirect_uri`.
  """
  @callback get_by(
    params :: [value: String.t(), redirect_uri: String.t()]
  ) :: token :: Boruta.Oauth.Token | nil

  @doc """
  Persists a token according to given params.
  """
  @callback create(params :: %{
    :client => Boruta.Oauth.Client.t(),
    :resource_owner => struct(),
    :redirect_uri => String.t(),
    :scope => String.t(),
    :state => String.t()
  }) :: code :: Boruta.Oauth.Token.t() | {:error, Ecto.Changeset.t()}
end
