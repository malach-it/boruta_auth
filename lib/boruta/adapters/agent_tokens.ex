defmodule Boruta.AgentTokensAdapter do
  @moduledoc """
  Encapsulate injected `Boruta.Oauth.AgentTokens` adapter in context configuration
  """

  @behaviour Boruta.Oauth.AgentTokens

  import Boruta.Config, only: [access_tokens: 0]

  def get_by(params), do: access_tokens().get_by(params)
  def create(params, opts), do: access_tokens().create(params, opts)
  def revoke(token), do: access_tokens().revoke(token)
  def revoke_refresh_token(token), do: access_tokens().revoke_refresh_token(token)
end
