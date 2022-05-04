defmodule Boruta.Migrations.OpenidConnect do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def up do
        # 20210720134116_add_default_to_scopes_name.exs
        alter table(:scopes) do
          modify(:name, :string, default: "")
        end

        # 20210720134125_add_default_to_tokens_scope.exs
        alter table(:tokens) do
          modify(:scope, :string, default: "")
        end

        # 20210721213916_add_nonce_to_tokens.exs
        alter table(:tokens) do
          add(:nonce, :string)
        end

        # 20210721200708_add_id_token_ttl_to_clients.exs
        alter table(:clients) do
          add(:id_token_ttl, :integer, default: 3600)
        end

        # 20210824204150_add_oauth_prefix.exs
        drop(unique_index(:clients, [:id, :secret]))
        drop(index(:tokens, [:value]))
        drop(unique_index(:tokens, [:client_id, :value]))
        drop(unique_index(:tokens, [:client_id, :refresh_token]))
        drop(unique_index(:scopes, [:name]))

        drop(constraint(:clients_scopes, "clients_scopes_client_id_fkey"))
        drop(constraint(:clients_scopes, "clients_scopes_scope_id_fkey"))
        drop(constraint(:tokens, "tokens_client_id_fkey"))

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
        # 20210824204150_add_oauth_prefix.exs
        drop(unique_index(:oauth_clients, [:id, :secret]))
        drop(index(:oauth_tokens, [:value]))
        drop(unique_index(:oauth_tokens, [:client_id, :value]))
        drop(unique_index(:oauth_tokens, [:client_id, :refresh_token]))
        drop(unique_index(:oauth_scopes, [:name]))

        drop(constraint(:oauth_clients_scopes, "oauth_clients_scopes_client_id_fkey"))
        drop(constraint(:oauth_clients_scopes, "oauth_clients_scopes_scope_id_fkey"))
        drop(constraint(:oauth_tokens, "oauth_tokens_client_id_fkey"))

        rename(table(:oauth_tokens), to: table(:tokens))
        rename(table(:oauth_clients), to: table(:clients))
        rename(table(:oauth_scopes), to: table(:scopes))
        rename(table(:oauth_clients_scopes), to: table(:clients_scopes))

        # migration history changed, for old migrations retrocompatibility
        drop_if_exists(constraint(:clients_scopes, "clients_scopes_client_id_fkey"))
        drop_if_exists(constraint(:clients_scopes, "clients_scopes_scope_id_fkey"))
        drop_if_exists(constraint(:tokens, "tokens_client_id_fkey"))

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

        # 20210721200708_add_id_token_ttl_to_clients.exs
        alter table(:clients) do
          remove(:id_token_ttl)
        end

        # 20210721213916_add_nonce_to_tokens.exs
        alter table(:tokens) do
          remove(:nonce)
        end

        # 20210720134125_add_default_to_tokens_scope.exs
        alter table(:tokens) do
          modify(:scope, :string)
        end

        # 20210720134116_add_default_to_scopes_name.exs
        alter table(:scopes) do
          modify(:name, :string)
        end
      end
    end
  end
end
