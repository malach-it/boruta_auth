defmodule Boruta.Repo.Migrations.AddRequestedScopeToOauthTokens do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add(:requested_scope, :string)
    end
  end
end
