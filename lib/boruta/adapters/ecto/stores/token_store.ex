defmodule Boruta.Ecto.TokenStore do
  @moduledoc false

  alias Boruta.Cache
  alias Boruta.Oauth.Token

  @spec get([value: String.t(), redirect_uri: String.t()] | [value: String.t()] | [refresh_token: String.t()]) ::
    {:ok, token :: Boruta.Oauth.Token.t()} | {:error, reason :: String.t()}
  def get(params) do
    case Keyword.get(params, :value) do
      nil -> {:error, "Not cached."}
      value -> get_by_value(value)
    end
  end
  defp get_by_value(""), do: {:error, "Not cached."}
  defp get_by_value(value) when is_binary(value) do
    case Cache.get({Token, value}) do
      nil -> {:error, "Not cached."}
      %Token{} = token -> {:ok, token}
    end
  end

  @spec put(token :: Boruta.Oauth.Token.t()) ::
    {:ok, token :: Boruta.Oauth.Token.t()}
  def put(token) do
    with :ok <- Cache.put({Token, token.value}, token) do
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
