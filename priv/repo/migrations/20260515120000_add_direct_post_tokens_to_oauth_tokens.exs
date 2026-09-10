defmodule Boruta.Repo.Migrations.AddDirectPostTokensToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add(:id_token, :text)
    end
  end
end
