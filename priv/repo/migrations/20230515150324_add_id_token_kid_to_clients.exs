defmodule Boruta.Repo.Migrations.AddIdTokenKidToClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :id_token_kid, :string
    end
  end
end
