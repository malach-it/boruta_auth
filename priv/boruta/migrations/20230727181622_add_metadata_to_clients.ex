defmodule Boruta.Migrations.AddMetadataToClients do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20230727160245_add_metadata_to_clients.exs
        alter table(:oauth_clients) do
          add :metadata, :jsonb, default: "{}", null: false
          add :logo_uri, :string
        end
      end
    end
  end
end

