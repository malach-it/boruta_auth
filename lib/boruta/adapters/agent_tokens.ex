defmodule Boruta.AgentTokensAdapter do
  @moduledoc """
  Encapsulate injected `Boruta.Oauth.AgentTokens` adapter in context configuration
  """

  @behaviour Boruta.Oauth.AgentTokens

  import Boruta.Config, only: [agent_tokens: 0]

  def get_by(params), do: agent_tokens().get_by(params)
  def create(params, opts), do: agent_tokens().create(params, opts)
  def revoke(token), do: agent_tokens().revoke(token)
  def revoke_refresh_token(token), do: agent_tokens().revoke_refresh_token(token)
  def claims_from_agent_token(token), do: agent_tokens().claims_from_agent_token(token)
end
