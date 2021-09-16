defmodule Boruta.Repo.Migrations.AddPublicRefreshTokenToClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :public_refresh_token, :boolean, null: false, default: false
    end
  end
end
