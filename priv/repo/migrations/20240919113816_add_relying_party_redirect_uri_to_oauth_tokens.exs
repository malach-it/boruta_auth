defmodule Boruta.Repo.Migrations.AddRelyingPartyRedirectUriToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :relying_party_redirect_uri, :string
    end
  end
end
