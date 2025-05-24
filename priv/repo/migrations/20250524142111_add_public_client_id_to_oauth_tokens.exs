defmodule Boruta.Repo.Migrations.AddPublicClientIdToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :public_client_id, :text
    end

    alter table(:oauth_clients) do
      add :check_public_client_id, :boolean, default: false, null: false
    end
  end
end
