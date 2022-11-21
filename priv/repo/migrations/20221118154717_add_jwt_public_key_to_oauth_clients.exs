defmodule Boruta.Repo.Migrations.AddJwtPublicKeyToOauthClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :jwt_public_key, :text
    end
  end
end
