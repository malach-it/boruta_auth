defmodule Boruta.Migrations.Oid4vciImplementation do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20231217141452_add_authorization_details_to_oauth_tokens.exs
        alter table(:oauth_tokens) do
          add :authorization_details, :jsonb, default: "[]"
        end
      end
    end
  end
end

