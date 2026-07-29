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
  @spec token(
          request :: RevokeRequest.t()
        ) ::
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
      value
      |> find_token(token_type_hint)
      |> revoke_token()
    end
  end

  defp find_token(value, "refresh_token") do
    with nil <- Boruta.AccessTokensAdapter.get_by(refresh_token: value) do
      Boruta.AccessTokensAdapter.get_by(value: value)
    end
  end

  defp find_token(value, _token_type_hint) do
    with nil <- Boruta.AccessTokensAdapter.get_by(value: value) do
      Boruta.AccessTokensAdapter.get_by(refresh_token: value)
    end
  end

  # Return :ok even for unexisting tokens.
  defp revoke_token(nil), do: :ok

  defp revoke_token(token) do
    with {:ok, _token} <- Boruta.AccessTokensAdapter.revoke(token) do
      :ok
    end
  end
end
