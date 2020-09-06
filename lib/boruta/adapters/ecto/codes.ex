defmodule Boruta.Ecto.Codes do
  @moduledoc false
  @behaviour Boruta.Oauth.Codes

  import Boruta.Config, only: [repo: 0]
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  alias Boruta.Ecto
  alias Boruta.Oauth.Client
  alias Boruta.Ecto.TokenStore

  @impl Boruta.Oauth.Codes
  def get_by([value: value, redirect_uri: redirect_uri] = attrs) do
    case TokenStore.get(attrs) do
      {:ok, token} -> token
      {:error, _reason} ->
        repo().get_by(Ecto.Token, type: "code", value: value, redirect_uri: redirect_uri)
        |> to_oauth_schema()
      end
  end

  @impl Boruta.Oauth.Codes
  def create(
        %{
          client: %Client{
            id: client_id,
            authorization_code_ttl: authorization_code_ttl
          } = client,
          redirect_uri: redirect_uri,
          scope: scope,
          state: state,
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method
        } = params
      ) do
    sub = params[:sub]

    changeset =
      apply(Ecto.Token, changeset_method(client), [
        %Ecto.Token{},
        %{
          client_id: client_id,
          sub: sub,
          redirect_uri: redirect_uri,
          state: state,
          scope: scope,
          authorization_code_ttl: authorization_code_ttl,
          code_challenge: code_challenge,
          code_challenge_method: code_challenge_method
        }
      ])

    with {:ok, token} <- repo().insert(changeset),
      {:ok, token} <- TokenStore.put(to_oauth_schema(token)) do
      {:ok, token}
    end
  end

  defp changeset_method(%Client{pkce: false}), do: :code_changeset
  defp changeset_method(%Client{pkce: true}), do: :pkce_code_changeset
end
