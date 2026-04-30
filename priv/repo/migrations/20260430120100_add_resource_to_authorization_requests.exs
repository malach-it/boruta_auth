defmodule Boruta.Repo.Migrations.AddResourceToAuthorizationRequests do
  use Ecto.Migration

  def change do
    alter table(:authorization_requests) do
      add :resource, :string
    end
  end
end
