defmodule Boruta.Migrations.CodeMetadataPolicy do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20250622144833_add_metadata_policy_to_oauth_tokens.exs
        alter table(:oauth_tokens) do
          add :metadata_policy, :jsonb, default: "{}"
        end
      end
    end
  end
end
