defmodule Boruta.Repo.Migrations.AddAgentTokenToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :agent_token, :string
    end
  end
end
