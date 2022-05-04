defmodule Boruta.Repo.Migrations.AddRefreshTokenTtlToClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :refresh_token_ttl, :integer, null: false, default: "2592000"
    end
  end
end
