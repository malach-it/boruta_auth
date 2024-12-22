defmodule Boruta.Migrations.AgentCredentials do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20241221205452_add_bind_data_to_oauth_tokens.exs
        alter table(:oauth_clients) do
          add :agent_token_ttl, :integer, null: false, default: agent_token_max_ttl()
        end

        alter table(:oauth_tokens) do
          add :bind_data, :jsonb
          add :bind_configuration, :jsonb
        end

        # 20241221232600_add_agent_token_to_oauth_tokens.exs
        alter table(:oauth_token) do
          add :agent_token, :string
        end
      end
    end
  end
end
