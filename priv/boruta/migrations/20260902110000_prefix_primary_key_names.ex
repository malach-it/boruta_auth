defmodule Boruta.Migrations.PrefixPrimaryKeyNames do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      @renames [
        {"oauth_clients", "clients_pkey", "oauth_clients_pkey"},
        {"oauth_tokens", "tokens_pkey", "oauth_tokens_pkey"},
        {"oauth_scopes", "scopes_pkey", "oauth_scopes_pkey"},
        {"oauth_clients_scopes", "clients_scopes_pkey", "oauth_clients_scopes_pkey"}
      ]

      @sequence {"clients_scopes_id_seq", "oauth_clients_scopes_id_seq"}

      def up do
        Enum.each(@renames, fn {table, from, to} -> rename_constraint(table, from, to) end)
        {from, to} = @sequence
        rename_sequence(from, to)
      end

      def down do
        {from, to} = @sequence
        rename_sequence(to, from)
        Enum.each(@renames, fn {table, from, to} -> rename_constraint(table, to, from) end)
      end

      defp rename_constraint(table, from, to) do
        qualified = qualify(table)

        execute("""
        DO $$ BEGIN
          IF EXISTS (
            SELECT 1 FROM pg_constraint
            WHERE conname = '#{from}' AND conrelid = '#{qualified}'::regclass
          ) THEN
            ALTER TABLE #{qualified} RENAME CONSTRAINT #{from} TO #{to};
          END IF;
        END $$;
        """)
      end

      defp rename_sequence(from, to) do
        qualified = qualify(from)

        execute("""
        DO $$ BEGIN
          IF to_regclass('#{qualified}') IS NOT NULL THEN
            ALTER SEQUENCE #{qualified} RENAME TO #{to};
          END IF;
        END $$;
        """)
      end

      defp qualify(name) do
        case prefix() do
          nil -> name
          prefix -> "#{prefix}.#{name}"
        end
      end
    end
  end
end
