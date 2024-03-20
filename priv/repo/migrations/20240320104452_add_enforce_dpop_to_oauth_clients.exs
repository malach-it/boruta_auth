defmodule Boruta.Repo.Migrations.AddEnforceDpopToOauthClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :enforce_dpop, :boolean, default: false
    end
  end
end
