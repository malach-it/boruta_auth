defmodule Boruta.Migrations.DpopImplementation do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20240320104452_add_enforce_dpop_to_oauth_clients.exs
        alter table(:oauth_clients) do
          add :enforce_dpop, :boolean, default: false
        end
      end
    end
  end
end

