defmodule Boruta.Repo.Migrations.AddOauthPrefix do
  use Ecto.Migration

  def up do
    drop(unique_index(:clients, [:id, :secret]))
    drop(index(:tokens, [:value]))
    drop(unique_index(:tokens, [:client_id, :value]))
    drop(unique_index(:tokens, [:client_id, :refresh_token]))
    drop(unique_index(:scopes, [:name]))

    drop constraint(:clients_scopes, "clients_scopes_client_id_fkey")
    drop constraint(:clients_scopes, "clients_scopes_scope_id_fkey")
    drop constraint(:tokens, "tokens_client_id_fkey")

    rename(table(:tokens), to: table(:oauth_tokens))
    rename(table(:clients), to: table(:oauth_clients))
    rename(table(:scopes), to: table(:oauth_scopes))
    rename(table(:clients_scopes), to: table(:oauth_clients_scopes))

    alter table(:oauth_clients_scopes) do
      modify(:client_id, references(:oauth_clients, type: :uuid, on_delete: :delete_all))
      modify(:scope_id, references(:oauth_scopes, type: :uuid, on_delete: :delete_all))
    end

    alter table(:oauth_tokens) do
      modify(:client_id, references(:oauth_clients, type: :uuid, on_delete: :nilify_all))
    end

    create(unique_index(:oauth_clients, [:id, :secret]))
    create(index(:oauth_tokens, [:value]))
    create(unique_index(:oauth_tokens, [:client_id, :value]))
    create(unique_index(:oauth_tokens, [:client_id, :refresh_token]))
    create(unique_index(:oauth_scopes, [:name]))
  end

  def down do
    drop(unique_index(:oauth_clients, [:id, :secret]))
    drop(index(:oauth_tokens, [:value]))
    drop(unique_index(:oauth_tokens, [:client_id, :value]))
    drop(unique_index(:oauth_tokens, [:client_id, :refresh_token]))
    drop(unique_index(:oauth_scopes, [:name]))

    drop constraint(:oauth_clients_scopes, "oauth_clients_scopes_client_id_fkey")
    drop constraint(:oauth_clients_scopes, "oauth_clients_scopes_scope_id_fkey")
    drop constraint(:oauth_tokens, "oauth_tokens_client_id_fkey")

    rename(table(:oauth_tokens), to: table(:tokens))
    rename(table(:oauth_clients), to: table(:clients))
    rename(table(:oauth_scopes), to: table(:scopes))
    rename(table(:oauth_clients_scopes), to: table(:clients_scopes))

    alter table(:clients_scopes) do
      modify(:client_id, references(:clients, type: :uuid, on_delete: :delete_all))
      modify(:scope_id, references(:scopes, type: :uuid, on_delete: :delete_all))
    end

    alter table(:tokens) do
      modify(:client_id, references(:clients, type: :uuid, on_delete: :nilify_all))
    end

    create(unique_index(:clients, [:id, :secret]))
    create(index(:tokens, [:value]))
    create(unique_index(:tokens, [:client_id, :value]))
    create(unique_index(:tokens, [:client_id, :refresh_token]))
    create(unique_index(:scopes, [:name]))
  end
end
