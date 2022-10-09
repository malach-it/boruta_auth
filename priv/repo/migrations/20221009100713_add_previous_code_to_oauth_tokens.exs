defmodule Boruta.Repo.Migrations.AddPreviousCodeToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add :previous_code, :string
    end
  end
end
