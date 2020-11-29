defmodule Boruta.Ecto.Codes do
  @moduledoc false
  @behaviour Boruta.Oauth.Codes

  import Boruta.Config, only: [repo: 0]
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  alias Boruta.Ecto
  alias Boruta.Oauth.Client

  @impl Boruta.Oauth.Codes
  def get_by(value: value, redirect_uri: redirect_uri) do
    repo().get_by(Ecto.Token, type: "code", value: value, redirect_uri: redirect_uri)
    |> to_oauth_schema()
  end

  @impl Boruta.Oauth.Codes
  def create(
        %{
          client: %Client{
            id: client_id,
            authorization_code_ttl: authorization_code_ttl
          },
          redirect_uri: redirect_uri,
          scope: scope,
          state: state,
        } = params
      ) do
    sub = params[:sub]

    changeset =
      Ecto.Token.code_changeset(%Ecto.Token{}, %{
        client_id: client_id,
        sub: sub,
        redirect_uri: redirect_uri,
        state: state,
        scope: scope,
        authorization_code_ttl: authorization_code_ttl
      })

    with {:ok, token} <- repo().insert(changeset) do
      {:ok, to_oauth_schema(token)}
    end
  end
end
