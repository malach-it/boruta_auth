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
          request :: %RevokeRequest{
            client_id: String.t(),
            client_secret: String.t(),
            token: String.t()
          }
        ) ::
          :ok
          | {:error, error :: Boruta.Oauth.Error.t()}
          | {:error, error :: String.t()}
  def token(%RevokeRequest{
        client_id: client_id,
        client_secret: client_secret,
        token: value,
        token_type_hint: token_type_hint
      }) do
    with {:ok, _client} <-
           Authorization.Client.authorize(
             id: client_id,
             secret: client_secret,
             grant_type: "revoke"
           ) do
      token =
        case token_type_hint do
          "refresh_token" ->
            with nil <- Boruta.AccessTokensAdapter.get_by(value: value) do
              Boruta.AccessTokensAdapter.get_by(refresh_token: value)
            end

          _ ->
            with nil <- Boruta.AccessTokensAdapter.get_by(refresh_token: value) do
              Boruta.AccessTokensAdapter.get_by(value: value)
            end
        end

      if token do
        with {:ok, _token} <- Boruta.AccessTokensAdapter.revoke(token) do
          :ok
        end
      else
        # return :ok even for unexisting tokens
        :ok
      end
    end
  end
end
