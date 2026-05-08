defmodule Boruta.Repo.Migrations.AddOauthResourceIndicators do
  use Ecto.Migration

  def change do
    alter table(:oauth_tokens) do
      add(:resource, :text)
    end

    alter table(:authorization_requests) do
      add(:resource, :text)
    end

    alter table(:oauth_clients) do
      add(:authorized_resources, {:array, :text}, default: [], null: false)
    end
  end
end
