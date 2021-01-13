defmodule Boruta.Ecto.TokenStore do
  @moduledoc false

  alias Boruta.Cache
  alias Boruta.Oauth.Client
  alias Boruta.Oauth.Token

  @spec get([value: String.t()] | [refresh_token: String.t()]) ::
    {:ok, token :: Boruta.Oauth.Token.t()} | {:error, reason :: String.t()}
  def get(value: value) do
    case Cache.get({Token, value}) do
      nil -> {:error, "Not cached."}
      %Token{} = token -> {:ok, token}
    end
  end
  def get(refresh_token: refresh_token) do
    case Cache.get({Token, refresh_token}) do
      nil -> {:error, "Not cached."}
      %Token{} = token -> {:ok, token}
    end
  end

  @spec put(token :: Boruta.Oauth.Token.t()) ::
    {:ok, token :: Boruta.Oauth.Token.t()}
  def put(%Token{client: %Client{access_token_ttl: access_token_ttl}} = token) do
    with :ok <- Cache.put({Token, token.value}, token, ttl: access_token_ttl * 1000),
      :ok <- Cache.put({Token, token.refresh_token}, token, ttl: access_token_ttl * 1000) do
      {:ok, token}
    end
  end

  @spec invalidate(token :: Boruta.Oauth.Token.t()) ::
    {:ok, token :: Boruta.Oauth.Token.t()}
  def invalidate(token) do
    with :ok <- Cache.put({Token, token.value}, nil) do
      {:ok, token}
    end
  end
end
