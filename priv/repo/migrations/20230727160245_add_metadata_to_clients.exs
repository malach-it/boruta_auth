defmodule Boruta.Repo.Migrations.AddMetadataToClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :metadata, :jsonb, default: "{}", null: false
      add :logo_uri, :string
    end
  end
end
