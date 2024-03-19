defmodule Boruta.Repo.Migrations.AddAuthorizationDetailsToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :authorization_details, :jsonb, default: "[]"
    end
  end
end
