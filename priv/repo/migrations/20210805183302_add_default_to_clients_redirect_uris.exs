defmodule Boruta.Repo.Migrations.AddDefaultToClientsRedirectUris do
  use Ecto.Migration

  def up do
    alter table(:clients) do
      modify :redirect_uris, {:array, :string}, default: []
    end
  end

  def down do
    alter table(:clients) do
      modify :redirect_uris, {:array, :string}
    end
  end
end
