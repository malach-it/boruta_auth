defmodule Boruta.Repo.Migrations.AddDefaultToClientsRedirectUris do
  use Ecto.Migration

  def change do
    alter table(:clients) do
      modify :redirect_uris, {:array, :string}, default: []
    end
  end
end
