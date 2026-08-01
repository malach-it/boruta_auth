defmodule Boruta.Migrations.ClientsTrustedAuthorities do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        alter table(:oauth_clients) do
          add(:trusted_authorities, :text, default: "", null: false)
        end
      end
    end
  end
end
