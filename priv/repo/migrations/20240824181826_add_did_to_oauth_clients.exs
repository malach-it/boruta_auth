defmodule Boruta.Repo.Migrations.AddDidToOauthClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :did, :string
    end
  end
end
