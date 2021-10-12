defmodule Boruta.Repo.Migrations.AddIdTokenTtlToClients do
  use Ecto.Migration

  def change do
    alter table(:clients) do
      add :id_token_ttl, :integer, default: 3600
    end
  end
end
