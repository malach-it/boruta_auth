defmodule Boruta.Repo.Migrations.ModifyOauthClientsDid do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      modify :did, :text
    end
  end
end
