defmodule Boruta.Repo.Migrations.OptionalPublicKeyForOauthClients do
  use Ecto.Migration

  def up do
    alter table(:oauth_clients) do
      modify :public_key, :text, null: true
    end
  end

  def down do
    alter table(:oauth_clients) do
      modify :public_key, :text, null: false
    end
  end
end
