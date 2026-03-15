defmodule Boruta.Repo.Migrations.AddEnforceEncryptionToOauthClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add(:enforce_encryption, :boolean, default: false, null: false)
    end
  end
end
