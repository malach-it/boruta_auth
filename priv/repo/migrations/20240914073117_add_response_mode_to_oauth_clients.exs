defmodule Boruta.Repo.Migrations.AddResponseModeToOauthClients do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      add :response_mode, :string, default: "direct_post"
    end
  end
end
