defmodule Boruta.Oauth.Authorization.AgentToken do
  @moduledoc """
  Check against given params and return the corresponding agent token
  """

  alias Boruta.AgentTokensAdapter
  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.Error
  alias Boruta.Oauth.Token

  def authorize(agent_token: nil, resource_owner: resource_owner) do
    Authorization.ResourceOwner.authorize(resource_owner: resource_owner)
  end

  def authorize(agent_token: value, resource_owner: resource_owner) do
    with %Token{} = agent_token <- AgentTokensAdapter.get_by(value: value),
         {:ok, claims} <- AgentTokensAdapter.claims_from_agent_token(agent_token) do
      {:ok, %{resource_owner | extra_claims: claims}}
    else
      nil ->
        {:error, %Error{
          status: :unauthorized,
          error: :invalid_agent_token,
          error_description: "Agent token is invalid"
        }}
    end
  end
end
