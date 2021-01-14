defmodule Boruta.Ecto.TokenStore do
  @moduledoc false

  import Boruta.Config, only: [cache_backend: 0]

  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Token

  @spec get([value: String.t()] | [refresh_token: String.t()]) ::
          {:ok, token :: Boruta.Oauth.Token.t()} | {:error, reason :: String.t()}
  def get(value: value) do
    case cache_backend().get({Token, :value, value}) do
      nil -> {:error, "Not cached."}
      %Token{} = token -> {:ok, token}
    end
  end

  def get(refresh_token: refresh_token) do
    case cache_backend().get({Token, :refresh_token, refresh_token}) do
      nil -> {:error, "Not cached."}
      %Token{} = token -> {:ok, token}
    end
  end

  @spec put(token :: Boruta.Oauth.Token.t()) ::
          {:ok, token :: Boruta.Oauth.Token.t()}
  def put(
        %Token{type: "access_token", client: %Client{access_token_ttl: access_token_ttl}} = token
      ) do
    with :ok <-
           cache_backend().put({Token, :value, token.value}, token, ttl: access_token_ttl * 1000),
         :ok <-
           cache_backend().put({Token, :refresh_token, token.refresh_token}, token,
             ttl: access_token_ttl * 1000
           ) do
      {:ok, token}
    end
  end

  def put(
        %Token{type: "code", client: %Client{authorization_code_ttl: authorization_code_ttl}} =
          token
      ) do
    with :ok <-
           cache_backend().put({Token, :value, token.value}, token,
             ttl: authorization_code_ttl * 1000
           ),
         :ok <-
           cache_backend().put({Token, :refresh_token, token.refresh_token}, token,
             ttl: authorization_code_ttl * 1000
           ) do
      {:ok, token}
    end
  end

  @spec invalidate(token :: Boruta.Oauth.Token.t()) ::
          {:ok, token :: Boruta.Oauth.Token.t()}
  def invalidate(token) do
    with :ok <- cache_backend().delete({Token, :value, token.value}),
         :ok <- cache_backend().delete({Token, :refresh_token, token.refresh_token}) do
      {:ok, token}
    end
  end
end
