defmodule Boruta.Repo.Migrations.ChangeOauthTokensValueToText do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      modify :value, :text, from: :string
    end
  end
end
