defmodule Boruta.Migrations.ClientsDid do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20240824181826_add_did_to_oauth_clients.exs
        alter table(:oauth_clients) do
          add :did, :string
        end
      end
    end
  end
end

