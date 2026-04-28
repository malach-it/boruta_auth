defmodule Boruta.Migrations.RequestedScope do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20260428120000_add_requested_scope_to_oauth_tokens.exs
        alter table(:oauth_tokens) do
          add(:requested_scope, :string, default: "")
        end
      end
    end
  end
end
