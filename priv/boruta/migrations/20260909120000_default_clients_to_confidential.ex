defmodule Boruta.Migrations.DefaultClientsToConfidential do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        alter table(:oauth_clients) do
          modify(:confidential, :boolean,
            default: true,
            null: false,
            from: [default: false, null: false]
          )
        end
      end
    end
  end
end
