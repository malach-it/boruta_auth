defmodule Boruta.Repo.Migrations.AddPublicRevokeToClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :public_revoke, :boolean, null: false, default: false
    end
  end
end
