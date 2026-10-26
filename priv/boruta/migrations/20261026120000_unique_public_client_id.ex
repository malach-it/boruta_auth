defmodule Boruta.Migrations.UniquePublicClientId do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        create(unique_index(:oauth_clients, [:public_client_id]))
      end
    end
  end
end
