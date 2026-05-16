defmodule Boruta.Migrations.Siopv2Encryption do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20260210003645_add_client_encryption_to_oauth_tokens.exs
        alter table(:oauth_tokens) do
          add :client_encryption_key, :jsonb
          add :client_encryption_alg, :string
        end
      end
    end
  end
end
