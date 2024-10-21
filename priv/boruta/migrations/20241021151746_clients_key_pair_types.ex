defmodule Boruta.Migrations.ClientsKeyPairTypes do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20241021114643_add_key_pair_type_to_oauth_clients.exs
        alter table(:oauth_clients) do
          add :key_pair_type, :jsonb, default: ~s({
            "type": "rsa",
            "modulus_size": "1024",
            "exponent_size": "65537"
          })
        end

        execute("""
          UPDATE oauth_clients
          SET key_pair_type = '{"type": "ec", "curve": "P-256"}'
          WHERE public_client_id IS NOT NULL
        """)
      end
    end
  end
end
