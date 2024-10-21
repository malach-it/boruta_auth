defmodule Boruta.Repo.Migrations.AddKeyPairTypeToOauthClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :key_pair_type, :jsonb, default: ~s({
        "type": "rsa",
        "modulus_size": "1024",
        "exponent_size": "65537"
      })
    end

    execute("""
      UPDATE oauth_clients
      SET key_pair_type = '{"type": "ec", "curve": "P-256"}'
      WHERE public_client_id IS NOT NULL
    """)
  end
end
