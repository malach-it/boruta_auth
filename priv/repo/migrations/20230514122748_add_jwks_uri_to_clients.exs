defmodule Boruta.Repo.Migrations.AddJwksUriToClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :jwks_uri, :string
    end
  end
end
