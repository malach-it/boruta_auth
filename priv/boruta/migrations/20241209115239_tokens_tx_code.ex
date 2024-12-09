defmodule Boruta.Migrations.TokensTxCode do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20241209092043_add_tx_code_to_tokens.exs
        alter table(:oauth_tokens) do
          add :tx_code, :string
        end

        alter table(:oauth_clients) do
          add :enforce_tx_code, :boolean, null: false, default: false
        end
      end
    end
  end
end
