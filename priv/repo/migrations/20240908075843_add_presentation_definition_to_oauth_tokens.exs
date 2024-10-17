defmodule Boruta.Repo.Migrations.AddPresentationDefinitionToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :presentation_definition, :jsonb
    end
  end
end
