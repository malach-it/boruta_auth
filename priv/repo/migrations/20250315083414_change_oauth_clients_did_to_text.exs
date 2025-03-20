defmodule Boruta.Repo.Migrations.ChangeOauthClientsDidToText do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      modify :did, :text, from: :string
    end
  end
end
