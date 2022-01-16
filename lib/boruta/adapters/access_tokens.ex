defmodule Boruta.AccessTokensAdapter do
  @moduledoc """
  Encapsulate injected `Boruta.Oauth.AccessTokens` adapter in context configuration
  """

  @behaviour Boruta.Oauth.AccessTokens

  import Boruta.Config, only: [access_tokens: 0]

  def get_by(params), do: access_tokens().get_by(params)
  def create(params, opts), do: access_tokens().create(params, opts)
  def revoke(token), do: access_tokens().revoke(token)
end
