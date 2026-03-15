defmodule Boruta.Migrations.ClientsEnforceEncryption do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20260315090000_add_enforce_encryption_to_oauth_clients.exs
        alter table(:oauth_clients) do
          add(:enforce_encryption, :boolean, default: false, null: false)
        end
      end
    end
  end
end
