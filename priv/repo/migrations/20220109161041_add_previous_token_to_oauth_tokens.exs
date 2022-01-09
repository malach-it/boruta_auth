defmodule Boruta.Repo.Migrations.AddPreviousTokenToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :previous_token, :string
    end
  end
end
