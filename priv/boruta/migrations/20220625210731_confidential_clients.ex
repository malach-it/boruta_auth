defmodule Boruta.Migrations.ConfidentialClients do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20220625090332_add_confidential_to_oauth_clients.exs
        alter table(:oauth_clients) do
          add(:confidential, :boolean, default: false, null: false)
        end
      end
    end
  end
end
