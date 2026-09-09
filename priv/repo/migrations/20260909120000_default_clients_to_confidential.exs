defmodule Boruta.Repo.Migrations.DefaultClientsToConfidential do
  use Ecto.Migration

  def change do
    alter table(:oauth_clients) do
      modify(:confidential, :boolean,
        default: true,
        null: false,
        from: [default: false, null: false]
      )
    end
  end
end
