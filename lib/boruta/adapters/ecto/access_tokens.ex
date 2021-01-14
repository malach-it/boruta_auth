defmodule Boruta.Ecto.AccessTokens do
  @moduledoc false
  @behaviour Boruta.Oauth.AccessTokens

  import Boruta.Config, only: [repo: 0]
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]
  import Ecto.Query, only: [from: 2]

  alias Boruta.Ecto.Token
  alias Boruta.Ecto.TokenStore
  alias Boruta.Oauth
  alias Boruta.Oauth.Client
  alias Ecto.Changeset

  @impl Boruta.Oauth.AccessTokens
  def get_by(attrs) do
    case get_by(:from_cache, attrs) do
      {:ok, token} -> token
      {:error, _reason} -> get_by(:from_database, attrs)
    end
  end

  defp get_by(:from_cache, attrs), do: TokenStore.get(attrs)
  defp get_by(:from_database, value: value) do
    with %Token{} = token <- repo().one(
      from t in Token,
        left_join: c in assoc(t, :client),
        where: t.type == "access_token" and t.value == ^value
    ),
    {:ok, token} <- token |> to_oauth_schema() |> TokenStore.put() do
      token
    end
  end
  defp get_by(:from_database, refresh_token: refresh_token) do
    with %Token{} = token <- repo().one(
      from t in Token,
        left_join: c in assoc(t, :client),
        where: t.type == "access_token" and t.refresh_token == ^refresh_token
    ),
    {:ok, token} <- token |> to_oauth_schema() |> TokenStore.put() do
      token
    end
  end

  @impl Boruta.Oauth.AccessTokens
  def create(
        %{client: %Client{id: client_id, access_token_ttl: access_token_ttl}, scope: scope} = params,
        options
      ) do
    sub = params[:sub]
    state = params[:state]
    redirect_uri = params[:redirect_uri]

    token_attributes = %{
      client_id: client_id,
      sub: sub,
      redirect_uri: redirect_uri,
      state: state,
      scope: scope,
      access_token_ttl: access_token_ttl
    }

    changeset =
      apply(
        Token,
        changeset_method(options),
        [%Token{}, token_attributes]
      )

    with {:ok, token} <- repo().insert(changeset),
      {:ok, token} <- TokenStore.put(to_oauth_schema(token)) do
      {:ok, token}
    end
  end

  defp changeset_method(refresh_token: true), do: :changeset_with_refresh_token
  defp changeset_method(_options), do: :changeset

  @impl Boruta.Oauth.AccessTokens
  def revoke(%Oauth.Token{value: value}) do
    now = DateTime.utc_now()

    with {:ok, token} <- repo().get_by(Token, value: value)
      |> Changeset.change(revoked_at: now)
      |> repo().update(),
      {:ok, token} <- TokenStore.invalidate(to_oauth_schema(token)) do
      {:ok, token}
    end
  end
end
