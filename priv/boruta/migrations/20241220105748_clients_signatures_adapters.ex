defmodule Boruta.Migrations.ClientsSignaturesAdapters do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20241220082127_add_signatures_adapter_to_oauth_clients.exs
        alter table(:oauth_clients) do
          add :signatures_adapter, :string, null: false, default: "Elixir.Boruta.Internal.Signatures"
        end
      end
    end
  end
end

