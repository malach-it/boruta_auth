defmodule Boruta.Repo.Migrations.AddResourceToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :resource, :string
    end
  end
end
