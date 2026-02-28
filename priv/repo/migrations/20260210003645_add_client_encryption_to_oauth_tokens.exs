defmodule Boruta.Repo.Migrations.AddClientEncryptionToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :client_encryption_key, :jsonb
      add :client_encryption_alg, :string
    end
  end
end
