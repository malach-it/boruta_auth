defmodule Boruta.Repo.Migrations.AddResponseTypeToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :response_type, :string
    end
  end
end
