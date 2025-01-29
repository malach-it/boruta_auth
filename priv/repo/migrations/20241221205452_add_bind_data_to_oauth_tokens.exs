defmodule Boruta.Repo.Migrations.AddBindDataToOauthTokens do
  use Ecto.Migration
  import Boruta.Config, only: [agent_token_max_ttl: 0]

  def change do
    alter table(:oauth_clients) do
      add :agent_token_ttl, :integer, null: false, default: agent_token_max_ttl()
    end

    alter table(:oauth_tokens) do
      add :bind_data, :jsonb
      add :bind_configuration, :jsonb
    end
  end
end
