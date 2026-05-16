defmodule Boruta.Repo.Migrations.AddMetadataPolicyToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :metadata_policy, :jsonb, default: "{}"
    end
  end
end
