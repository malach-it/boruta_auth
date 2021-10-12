defmodule Boruta.Migrations.OpenidConnect do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
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
    end
  end
end
