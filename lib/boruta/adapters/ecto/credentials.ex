defmodule Boruta.Ecto.Credentials do
  @moduledoc false
  @behaviour Boruta.Openid.Credentials

  import Boruta.Config, only: [repo: 0]
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  alias Boruta.Ecto

  @impl Boruta.Openid.Credentials
  def get_by(access_token: access_token) do
    with %Ecto.Credential{} = credential <- repo().get_by(Ecto.Credential, access_token: access_token) do
      to_oauth_schema(credential)
    end
  end

  @impl Boruta.Openid.Credentials
  def create_credential(credential, token) do
    attrs = %{
      credential: credential.credential,
      format: credential.format,
      defered: credential.defered,
      access_token: token.value
    }

    with {:ok, credential} <-
           Ecto.Credential.create_changeset(%Ecto.Credential{}, attrs)
           |> repo().insert() do
      {:ok, to_oauth_schema(credential)}
    end
  end
end
