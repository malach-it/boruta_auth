defmodule Boruta.Repo.Migrations.AddAccessTokenTtlToClients do
  use Ecto.Migration

  def change do
    alter table(:clients) do
      add(:authorization_code_ttl, :integer, null: false)
      add(:access_token_ttl, :integer, null: false)
    end
  end
end
