defmodule Boruta.Repo.Migrations.AddConfidentialToOauthClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :confidential, :boolean, default: false, null: false
    end
  end
end
