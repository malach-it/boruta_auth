defmodule Boruta.Migrations.OpenidConnect do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        alter table(:scopes) do
          modify(:name, :string, default: "")
        end

        alter table(:tokens) do
          modify(:scope, :string, default: "")
          add(:nonce, :string)
        end

        alter table(:clients) do
          add(:id_token_ttl, :integer, default: 3600)
        end
      end
    end
  end
end
