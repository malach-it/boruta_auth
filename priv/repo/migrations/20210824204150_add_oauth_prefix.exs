defmodule Boruta.Repo.Migrations.AddOauthPrefix do
  use Ecto.Migration

  def change do
    drop unique_index(:clients, [:id, :secret])
    drop index(:tokens, [:value])
    drop unique_index(:tokens, [:client_id, :value])
    drop unique_index(:tokens, [:client_id, :refresh_token])
    drop unique_index(:scopes, [:name])

    rename table(:tokens), to: table(:oauth_tokens)
    rename table(:clients), to: table(:oauth_clients)
    rename table(:scopes), to: table(:oauth_scopes)
    rename table(:clients_scopes), to: table(:oauth_clients_scopes)

    create unique_index(:oauth_clients, [:id, :secret])
    create index(:oauth_tokens, [:value])
    create unique_index(:oauth_tokens, [:client_id, :value])
    create unique_index(:oauth_tokens, [:client_id, :refresh_token])
    create unique_index(:oauth_scopes, [:name])
  end
end
