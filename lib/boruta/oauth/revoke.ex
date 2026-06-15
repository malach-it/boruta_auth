defmodule Boruta.Oauth.Revoke do
  @moduledoc """
  Access token revocation
  """

  alias Boruta.Oauth.Authorization
  alias Boruta.Oauth.RevokeRequest

  @doc """
  Revokes token according to the given `Boruta.Oauth.RevokeRequest`
  ## Examples
      iex> token(%RevokeRequest{
        client_id: "client_id",
        client_secret: "client_secret",
        token: "token"
      })
      :ok
  """
  @spec token(request :: RevokeRequest.t()) ::
          :ok
          | {:error, error :: Boruta.Oauth.Error.t()}
          | {:error, error :: String.t()}
  def token(%RevokeRequest{
        client_id: client_id,
        client_authentication: client_source,
        token: value,
        token_type_hint: token_type_hint
      }) do
    with {:ok, _client} <-
           Authorization.Client.authorize(
             id: client_id,
             source: client_source,
             grant_type: "revoke"
           ) do
      case token_adapter(token_type_hint, value) do
        {adapter, token} ->
          with {:ok, _token} <- adapter.revoke(token) do
            :ok
          end

        nil ->
          # return :ok even for unexisting tokens
          :ok
      end
    end
  end

  defp token_adapter("refresh_token", value) do
    find_token(:refresh_token, value) ||
      find_token(:value, value)
  end

  defp token_adapter(_token_type_hint, value) do
    find_token(:value, value) ||
      find_token(:refresh_token, value)
  end

  defp find_token(field, value) do
    access_token(field, value) || agent_token(field, value)
  end

  defp access_token(:value, value),
    do: token(Boruta.AccessTokensAdapter, "access_token", value: value)

  defp access_token(:refresh_token, value),
    do: token(Boruta.AccessTokensAdapter, "access_token", refresh_token: value)

  defp agent_token(:value, value),
    do: token(Boruta.AgentTokensAdapter, "agent_token", value: value)

  defp agent_token(:refresh_token, value),
    do: token(Boruta.AgentTokensAdapter, "agent_token", refresh_token: value)

  defp token(adapter, type, params) do
    case adapter.get_by(params) do
      %{type: ^type} = token -> {adapter, token}
      _ -> nil
    end
  end
end
