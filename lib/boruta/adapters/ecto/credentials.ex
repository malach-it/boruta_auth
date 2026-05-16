defmodule Boruta.Ecto.Credentials do
  @moduledoc false
  @behaviour Boruta.Openid.Credentials

  import Boruta.Config, only: [repo: 0]
  import Boruta.Ecto.OauthMapper, only: [to_oauth_schema: 1]

  alias Boruta.Ecto
  alias Boruta.Ecto.Token

  @impl Boruta.Openid.Credentials
  def get_by(access_token: access_token) do
    with %Ecto.Credential{} = credential <-
           repo().get_by(Ecto.Credential, access_token: access_token) do
      to_oauth_schema(credential)
    end
  end

  @impl Boruta.Openid.Credentials
  def create_credential(credential, token) do
    credential_token_attrs = %{
      client_id: token.client.id,
      sub: token.sub,
      redirect_uri: token.redirect_uri,
      state: token.state,
      nonce: token.nonce,
      scope: token.scope,
      requested_scope: token.requested_scope,
      resource: token.resource,
      previous_code: token.value,
      authorization_details: token.authorization_details,
      agent_token: token.agent_token,
      expires_at: token.expires_at
    }

    with {:ok, _credential_token} <-
           Token.credential_changeset(%Token{}, credential_token_attrs)
           |> repo().insert() do
      maybe_create_defered_credential(credential, token)
    end
  end

  defp maybe_create_defered_credential(%{defered: true} = credential, token) do
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

  defp maybe_create_defered_credential(credential, _token), do: {:ok, credential}
end
