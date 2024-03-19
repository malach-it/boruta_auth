defmodule Boruta.Repo.Migrations.ChangeOauthTokenSub do
  use Ecto.Migration

  def up do
    alter table(:oauth_tokens) do
      modify :sub, :text
    end
  end

  def down do
    alter table(:oauth_tokens) do
      modify :sub, :string
    end
  end
end
